package app.morphe.verifier;

import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.StringReference;
import org.jf.dexlib2.util.ReferenceUtil;

import java.io.Serializable;
import java.util.*;

/**
 * Streaming Multi-DEX Reachability and Call-Graph Indexing Engine with
 * Interface and Inheritance Hierarchy Resolution.
 */
public final class DexReachabilityEngine implements Serializable {

    public enum CallerType {
        UI_VIEW_MODEL,
        WORKER_SERVICE,
        INTERNAL_LOGIC,
        LEGACY_OR_UNRESOLVED
    }

    public static class CallerSite implements Serializable {
        public final String callerClass;
        public final String callerMethod;
        public final String targetDescriptor;
        public final CallerType callerType;
        public final int instructionIndex;

        public CallerSite(String callerClass, String callerMethod, String targetDescriptor,
                          CallerType callerType, int instructionIndex) {
            this.callerClass = callerClass;
            this.callerMethod = callerMethod;
            this.targetDescriptor = targetDescriptor;
            this.callerType = callerType;
            this.instructionIndex = instructionIndex;
        }

        @Override
        public String toString() {
            return callerClass + "->" + callerMethod + " [" + callerType + "]";
        }
    }

    private final Map<String, List<CallerSite>> callersByMethodDescriptor = new HashMap<>();
    private final Map<String, List<CallerSite>> callersByMethodName = new HashMap<>();
    private final Map<String, Set<String>> classParentsAndInterfaces = new HashMap<>();
    private final Set<String> invokedMethodDescriptors = new HashSet<>();
    private final Set<String> referencedFieldDescriptors = new HashSet<>();
    private final Set<String> referencedClasses = new HashSet<>();
    private final Set<String> stringConstants = new HashSet<>();

    private int totalInstructionsScanned = 0;
    private int totalClassesScanned = 0;

    public DexReachabilityEngine() {}

    public static DexReachabilityEngine buildFromDexFiles(Iterable<? extends DexBackedDexFile> dexFiles) {
        DexReachabilityEngine engine = new DexReachabilityEngine();
        if (dexFiles != null) {
            for (DexBackedDexFile dex : dexFiles) {
                if (dex != null) engine.indexDexFile(dex);
            }
        }
        return engine;
    }

    public static DexReachabilityEngine buildFromDexFiles(DexBackedDexFile... dexFiles) {
        DexReachabilityEngine engine = new DexReachabilityEngine();
        if (dexFiles != null) {
            for (DexBackedDexFile dex : dexFiles) {
                if (dex != null) engine.indexDexFile(dex);
            }
        }
        return engine;
    }

    public void indexDexFile(DexBackedDexFile dexFile) {
        if (dexFile == null) return;

        for (ClassDef classDef : dexFile.getClasses()) {
            if (classDef == null) continue;
            totalClassesScanned++;

            String classType = classDef.getType();
            referencedClasses.add(classType);

            Set<String> parents = classParentsAndInterfaces.computeIfAbsent(classType, k -> new HashSet<>());
            if (classDef.getSuperclass() != null) {
                referencedClasses.add(classDef.getSuperclass());
                parents.add(classDef.getSuperclass());
            }
            for (String iface : classDef.getInterfaces()) {
                if (iface != null) {
                    referencedClasses.add(iface);
                    parents.add(iface);
                }
            }

            CallerType classCallerType = classifyClass(classType);

            for (Method method : classDef.getMethods()) {
                if (method == null) continue;
                MethodImplementation impl = method.getImplementation();
                if (impl == null) continue;

                int instIdx = 0;
                for (Instruction inst : impl.getInstructions()) {
                    totalInstructionsScanned++;
                    if (inst instanceof ReferenceInstruction) {
                        ReferenceInstruction refInst = (ReferenceInstruction) inst;
                        Object ref = refInst.getReference();

                        if (ref instanceof MethodReference) {
                            MethodReference mRef = (MethodReference) ref;
                            String desc = ReferenceUtil.getMethodDescriptor(mRef);
                            invokedMethodDescriptors.add(desc);

                            CallerSite site = new CallerSite(classType, method.getName(), desc, classCallerType, instIdx);
                            callersByMethodDescriptor.computeIfAbsent(desc, k -> new ArrayList<>()).add(site);
                            callersByMethodName.computeIfAbsent(mRef.getName(), k -> new ArrayList<>()).add(site);

                            // Short key: Lclass;->method
                            String shortKey = mRef.getDefiningClass() + "->" + mRef.getName();
                            callersByMethodDescriptor.computeIfAbsent(shortKey, k -> new ArrayList<>()).add(site);

                        } else if (ref instanceof FieldReference) {
                            FieldReference fRef = (FieldReference) ref;
                            referencedFieldDescriptors.add(ReferenceUtil.getFieldDescriptor(fRef));
                            referencedClasses.add(fRef.getDefiningClass());
                        } else if (ref instanceof StringReference) {
                            stringConstants.add(((StringReference) ref).getString());
                        }
                    }
                    instIdx++;
                }
            }
        }
    }

    private static CallerType classifyClass(String classType) {
        if (classType == null) return CallerType.LEGACY_OR_UNRESOLVED;
        if (classType.contains("Activity") || classType.contains("Fragment") ||
            classType.contains("ViewModel") || classType.contains("View") ||
            classType.contains("Presenter") || classType.contains("Controller")) {
            return CallerType.UI_VIEW_MODEL;
        }
        if (classType.contains("Worker") || classType.contains("JobService") ||
            classType.contains("Service") || classType.contains("Receiver")) {
            return CallerType.WORKER_SERVICE;
        }
        return CallerType.INTERNAL_LOGIC;
    }

    public List<CallerSite> getCallersForMethod(String definingClass, String methodName) {
        List<CallerSite> results = new ArrayList<>();
        String directKey = definingClass + "->" + methodName;
        List<CallerSite> direct = callersByMethodDescriptor.get(directKey);
        if (direct != null) results.addAll(direct);

        // Check parents and interfaces
        Set<String> parents = classParentsAndInterfaces.get(definingClass);
        if (parents != null) {
            for (String p : parents) {
                List<CallerSite> pCallers = callersByMethodDescriptor.get(p + "->" + methodName);
                if (pCallers != null) {
                    for (CallerSite site : pCallers) {
                        if (!results.contains(site)) results.add(site);
                    }
                }
            }
        }

        // If direct is empty, check method name matches against known interfaces
        if (results.isEmpty()) {
            List<CallerSite> byName = callersByMethodName.get(methodName);
            if (byName != null) {
                for (CallerSite site : byName) {
                    if (parents != null) {
                        for (String p : parents) {
                            if (site.targetDescriptor.contains(p) && !results.contains(site)) {
                                results.add(site);
                            }
                        }
                    }
                }
            }
        }

        return Collections.unmodifiableList(results);
    }

    public List<CallerSite> getCallersForMethodName(String methodName) {
        List<CallerSite> callers = callersByMethodName.get(methodName);
        return callers != null ? Collections.unmodifiableList(callers) : Collections.emptyList();
    }

    public boolean isMethodInvoked(String definingClass, String methodName) {
        return !getCallersForMethod(definingClass, methodName).isEmpty();
    }

    public Set<String> getStringConstants() {
        return Collections.unmodifiableSet(stringConstants);
    }

    public int getTotalClassesScanned() {
        return totalClassesScanned;
    }

    public int getTotalInstructionsScanned() {
        return totalInstructionsScanned;
    }

    public int getUniqueMethodsInvokedCount() {
        return invokedMethodDescriptors.size();
    }
}
