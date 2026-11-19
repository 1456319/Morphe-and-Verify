package app.morphe.manager.patcher.verification

import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.FieldReference
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import com.android.tools.smali.dexlib2.util.ReferenceUtil

/**
 * Streaming Multi-DEX Reachability and Call-Graph Indexing Engine.
 *
 * Scans Dalvik bytecode across multi-DEX APKs without excessive heap allocation,
 * indexing incoming method invocations, field references, and string pool literals.
 */
class DexReachabilityEngine {

    val callersByMethodDescriptor = mutableMapOf<String, MutableList<CallerSite>>()
    val callersByMethodName = mutableMapOf<String, MutableList<CallerSite>>()
    val classParentsAndInterfaces = mutableMapOf<String, MutableSet<String>>()
    val invokedMethodDescriptors = mutableSetOf<String>()
    val referencedFieldDescriptors = mutableSetOf<String>()
    val referencedClasses = mutableSetOf<String>()
    val stringConstants = mutableSetOf<String>()

    var totalInstructionsScanned = 0
        private set
    var totalClassesScanned = 0
        private set

    fun indexDexFile(dexFile: DexBackedDexFile?) {
        if (dexFile == null) return

        for (classDef in dexFile.classes) {
            totalClassesScanned++
            val classType = classDef.type
            referencedClasses.add(classType)

            val parents = classParentsAndInterfaces.getOrPut(classType) { mutableSetOf() }
            classDef.superclass?.let {
                referencedClasses.add(it)
                parents.add(it)
            }
            for (iface in classDef.interfaces) {
                referencedClasses.add(iface)
                parents.add(iface)
            }

            val isUi = classType.contains("Activity") ||
                    classType.contains("Fragment") ||
                    classType.contains("ViewModel") ||
                    classType.contains("View") ||
                    classType.contains("Presenter") ||
                    classType.contains("Controller")

            for (method in classDef.methods) {
                val impl = method.implementation ?: continue
                var instIdx = 0
                for (inst in impl.instructions) {
                    totalInstructionsScanned++
                    if (inst is ReferenceInstruction) {
                        when (val ref = inst.reference) {
                            is MethodReference -> {
                                val desc = ReferenceUtil.getMethodDescriptor(ref)
                                invokedMethodDescriptors.add(desc)

                                val site = CallerSite(classType, method.name, desc, isUi, instIdx)
                                callersByMethodDescriptor.getOrPut(desc) { mutableListOf() }.add(site)
                                callersByMethodName.getOrPut(ref.name) { mutableListOf() }.add(site)

                                val shortKey = "${ref.definingClass}->${ref.name}"
                                callersByMethodDescriptor.getOrPut(shortKey) { mutableListOf() }.add(site)
                            }
                            is FieldReference -> {
                                referencedFieldDescriptors.add(ReferenceUtil.getFieldDescriptor(ref))
                                referencedClasses.add(ref.definingClass)
                            }
                            is StringReference -> {
                                stringConstants.add(ref.string)
                            }
                        }
                    }
                    instIdx++
                }
            }
        }
    }

    fun getCallersForMethod(definingClass: String, methodName: String): List<CallerSite> {
        val results = mutableListOf<CallerSite>()
        val directKey = "$definingClass->$methodName"
        callersByMethodDescriptor[directKey]?.let { results.addAll(it) }

        // Interface and superclass hierarchy lookup
        classParentsAndInterfaces[definingClass]?.forEach { parent ->
            callersByMethodDescriptor["$parent->$methodName"]?.let { pCallers ->
                pCallers.forEach { if (it !in results) results.add(it) }
            }
        }

        if (results.isEmpty()) {
            callersByMethodName[methodName]?.forEach { site ->
                classParentsAndInterfaces[definingClass]?.forEach { parent ->
                    if (site.targetDescriptor.contains(parent) && site !in results) {
                        results.add(site)
                    }
                }
            }
        }

        return results
    }

    fun getCallersForMethodName(methodName: String): List<CallerSite> =
        callersByMethodName[methodName] ?: emptyList()

    companion object {
        fun buildFromDexFiles(dexFiles: Iterable<DexBackedDexFile>): DexReachabilityEngine {
            val engine = DexReachabilityEngine()
            dexFiles.forEach { engine.indexDexFile(it) }
            return engine
        }
    }
}
