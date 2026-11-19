package app.morphe.verifier;

import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.DexFile;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Concrete audit runner demonstrating the Patch Effectiveness Verification Engine
 * against real enterprise binaries (com.xfinity.digitalhome v6.14.0-2).
 */
public class RealBinaryAuditRunner {

    public static void main(String[] args) throws Exception {
        String dexPath = "/home/deck/.gemini/antigravity/scratch/xfinity_audit/stock_classes5.dex";
        if (args.length > 0) {
            dexPath = args[0];
        }

        File file = new File(dexPath);
        if (!file.exists()) {
            System.err.println("File not found: " + dexPath);
            System.exit(1);
        }

        System.out.println("Indexing DEX: " + file.getAbsolutePath());
        long start = System.currentTimeMillis();
        DexFile rawDex = DexFileFactory.loadDexFile(file, Opcodes.getDefault());
        DexBackedDexFile dex = (DexBackedDexFile) rawDex;

        DexReachabilityEngine reachability = DexReachabilityEngine.buildFromDexFiles(dex);
        long elapsed = System.currentTimeMillis() - start;
        System.out.println(String.format("Indexed %d classes, %d instructions in %d ms.\n",
                reachability.getTotalClassesScanned(), reachability.getTotalInstructionsScanned(), elapsed));

        PatchVerificationEngine engine = new PatchVerificationEngine(reachability);
        List<PatchVerificationEngine.PatchAuditReport> reports = new ArrayList<>();

        // ----------------------------------------------------
        // Patch 1: Disable AI (semicoloncolonel)
        // ----------------------------------------------------
        PatchVerificationEngine.PatchAuditReport r1 = engine.verifyPatch(
                "Disable AI (semicoloncolonel)",
                "Lcom/xfinity/digitalhome/manager/UserFeatureManager;",
                "getXfinityAssistantEnabled",
                1, // 1 instruction mutated (returnEarly false)
                Arrays.asList("getCoamActivationEnabled"),
                Arrays.asList("comcast/aiq", "supportsAssistant"),
                Arrays.asList("aiq.xa.comcast.net")
        );
        reports.add(r1);

        // ----------------------------------------------------
        // Patch 2: Block advertising & device IDs (Proteus)
        // ----------------------------------------------------
        PatchVerificationEngine.PatchAuditReport r2 = engine.verifyPatch(
                "Block advertising & device IDs (Proteus)",
                "Lcom/google/android/gms/ads/identifier/AdvertisingIdClient$Info;",
                "getId",
                0, // 0 mutations matched in Xfinity
                null,
                null,
                null
        );
        reports.add(r2);

        // ----------------------------------------------------
        // Patch 3: Block analytics & tracking SDKs (Proteus)
        // ----------------------------------------------------
        PatchVerificationEngine.PatchAuditReport r3 = engine.verifyPatch(
                "Block analytics & tracking SDKs (Proteus)",
                "Lcom/google/firebase/analytics/FirebaseAnalytics;",
                "logEvent",
                0, // 0 mutations matched in Xfinity
                null,
                null,
                null
        );
        reports.add(r3);

        // ----------------------------------------------------
        // Patch 4: Block analytics & tracking (semicoloncolonel)
        // ----------------------------------------------------
        PatchVerificationEngine.PatchAuditReport r4 = engine.verifyPatch(
                "Block analytics & tracking (semicoloncolonel)",
                "Lcom/xfinity/dh/analytics/sift/AnalyticsProcessor;",
                "configureAndInitializeTracker",
                6, // Sift tracker stubs applied
                null,
                Arrays.asList("datadog", "branchio"),
                Arrays.asList("sift.xfinity.com", "datadoghq.com")
        );
        reports.add(r4);

        // Output final breakdown
        String reportOutput = engine.generateFinalBreakdown(reports);
        System.out.println(reportOutput);
    }
}
