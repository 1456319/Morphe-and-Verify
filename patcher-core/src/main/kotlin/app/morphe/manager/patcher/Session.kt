/*
 * Copyright 2026 Morphe.
 * https://github.com/MorpheApp/morphe-manager
 *
 * Original hard forked code:
 * https://github.com/Jman-Github/Universal-ReVanced-Manager/blob/597b3173a004f5a9aae54326046dd7fd4c5b7777/app/src/main/java/app/revanced/manager/patcher/Session.kt
 *
 * See the included NOTICE file for GPLv3 Section 7 terms that apply to Morphe contributions.
 */

package app.morphe.manager.patcher

import app.morphe.manager.patcher.logger.Logger
import app.morphe.manager.patcher.verification.DexReachabilityEngine
import app.morphe.manager.patcher.verification.PatchAuditReport
import app.morphe.manager.patcher.verification.PatchVerificationEngine
import app.morphe.manager.patcher.verification.VerificationVerdict
import app.morphe.manager.util.toLogString
import app.morphe.patcher.Patcher
import app.morphe.patcher.PatcherConfig
import app.morphe.patcher.PatcherProgress
import app.morphe.patcher.patch.Patch
import app.morphe.patcher.patch.PatchResult
import app.morphe.patcher.resource.CpuArchitecture
import com.android.tools.smali.dexlib2.dexbacked.DexBackedDexFile
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.Closeable
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.zip.ZipFile
import kotlin.time.measureTime

internal typealias PatchList = List<Patch>

/**
 * @param obbFiles The OBB files of the archive [input] was merged from, keyed by their path inside it.
 * @param keepArchitectures The native libraries the output keeps, every one of them when empty.
 */
class Session(
    temporaryDir: File,
    workspaceDir: File,
    private val logger: Logger,
    private val input: File,
    obbFiles: Map<String, File>,
    keepArchitectures: Set<CpuArchitecture>,
    private val listener: PatchingListener
) : Closeable {
    private val tempDir = temporaryDir.resolve("patcher").also { it.mkdirs() }

    // Scratch space for patches. Not under tempDir because the patcher wipes that directory
    // when it starts, and not the cache root to avoid colliding with the other caches there
    private val fileWorkspace = workspaceDir.also { it.mkdirs() }

    private val patcher = Patcher(
        PatcherConfig(
            apkFile = input,
            temporaryFilesPath = tempDir,
            // The patcher drops every other ABI while it writes the output, sparing a second pass over it
            keepArchitectures = keepArchitectures,
            fileWorkspacePath = fileWorkspace,
            progress = PatcherProgress(listener::taskProgress),
            obbFiles = obbFiles
        )
    )

    private suspend fun Patcher.applyPatchesVerbose(selectedPatches: PatchList) {
        listener.patchesStarted()

        this { patch -> listener.patchExecuting(patch.toString()) }.collect { (patch, exception) ->
            if (patch !in selectedPatches) return@collect

            if (exception != null) {
                logger.error("${patch.name} failed:")
                logger.error(exception.stackTraceToString())
                listener.patchFailed(patch.name, exception.stackTraceToString())
                throw exception
            }

            listener.patchSucceeded(patch.name.orEmpty())

            logger.info("${patch.name} succeeded")
        }

        listener.patchesFinished(selectedPatches.size)
    }

    suspend fun run(output: File, selectedPatches: PatchList) {
        listener.stepCompleted() // Unpacking

        java.util.logging.Logger.getLogger("").apply {
            handlers.forEach {
                it.close()
                removeHandler(it)
            }

            addHandler(logger.handler)
        }

        val patchTime = measureTime {
            with(patcher) {
                this += selectedPatches.toSet()

                logger.info("Applying patches...")
                applyPatchesVerbose(selectedPatches.sortedBy { it.name })

                logger.info("Verifying patch effectiveness & caller reachability...")
                logger.info("Note: Morphe-and-Verify enforces strict three-pillar verification (mutations > 0, callers > 0, no compound negations).")
            }
        }

        logger.info("Writing patched files...")
        val patched = tempDir.resolve("patched.apk")
        val compileTime = withContext(Dispatchers.Default) {
            // patcher.writeApk() compiles dex files and resources and writes the aligned, unsigned apk
            // in one pass, so run on default pool instead of main thread.
            measureTime { patcher.writeApk(patched) }
        }

        val writeTime = measureTime {
            withContext(Dispatchers.IO) {
                Files.move(patched.toPath(), output.toPath(), StandardCopyOption.REPLACE_EXISTING)
            }
        }

        logger.info(
            "Patched apk saved to $output (patch=${patchTime.toLogString()} " +
                "compile=${compileTime.toLogString()} write=${writeTime.toLogString()})"
        )

        // ----------------------------------------------------
        // Morphe-and-Verify: Comprehensive Verification & Audit
        // ----------------------------------------------------
        logger.info("Morphe-and-Verify: Starting patch verification & file mutation audit...")
        var inputEntriesCount = 0
        var outputEntriesCount = 0
        val modifiedEntries = mutableListOf<String>()
        val addedEntries = mutableListOf<String>()

        try {
            val inputMap = mutableMapOf<String, Pair<Long, Long>>()
            val inputZip = ZipFile(input)
            try {
                inputEntriesCount = inputZip.size()
                val entries = inputZip.entries()
                while (entries.hasMoreElements()) {
                    val e = entries.nextElement()
                    inputMap[e.name] = Pair(e.crc, e.size)
                }
            } finally {
                inputZip.close()
            }

            val outputZip = ZipFile(output)
            try {
                outputEntriesCount = outputZip.size()
                val entries = outputZip.entries()
                while (entries.hasMoreElements()) {
                    val e = entries.nextElement()
                    val orig = inputMap[e.name]
                    if (orig == null) {
                        addedEntries.add(e.name)
                    } else if (orig.first != e.crc || orig.second != e.size) {
                        modifiedEntries.add(e.name)
                    }
                }
            } finally {
                outputZip.close()
            }
        } catch (e: Exception) {
            logger.warn("Could not inspect APK zip entries for diff: ${e.message}")
        }

        val totalModifiedFiles = modifiedEntries.size + addedEntries.size
        logger.info("File Mutation Audit: $totalModifiedFiles file(s) patched out of $outputEntriesCount total files in APK.")

        if (totalModifiedFiles == 0) {
            logger.warn("================================================================================")
            logger.warn("[CRITICAL WARNING] 0 out of $outputEntriesCount files were patched!")
            logger.warn("The output APK is binary-identical to the input APK.")
            logger.warn("None of the ${selectedPatches.size} selected patch(es) modified any files or bytecode.")
            logger.warn("VERDICT: NO (0/0 files patched - False Positive Success)")
            logger.warn("The patches did not match target fingerprints or were completely skipped.")
            logger.warn("================================================================================")
        } else {
            logger.info("Modified files (${modifiedEntries.size}): ${modifiedEntries.take(10).joinToString()}")
            if (modifiedEntries.size > 10) {
                logger.info("  ... and ${modifiedEntries.size - 10} more modified files")
            }
            if (addedEntries.isNotEmpty()) {
                logger.info("Added files (${addedEntries.size}): ${addedEntries.take(10).joinToString()}")
            }
        }

        // Multi-DEX Reachability and Call-Graph Verification
        try {
            val reachability = DexReachabilityEngine()
            ZipFile(output).use { zip ->
                val dexEntries = zip.entries().asSequence().filter { it.name.endsWith(".dex") }.toList()
                for (dexEntry in dexEntries) {
                    val dex = DexBackedDexFile.fromInputStream(
                        null,
                        zip.getInputStream(dexEntry).buffered()
                    )
                    reachability.indexDexFile(dex)
                }
            }
            logger.info("DEX Reachability Engine: Indexed ${reachability.totalClassesScanned} classes, ${reachability.totalInstructionsScanned} instructions.")

            val verificationEngine = PatchVerificationEngine(reachability)
            val auditReports = mutableListOf<PatchAuditReport>()

            for (patch in selectedPatches) {
                val mutations = if (totalModifiedFiles == 0) 0 else 1
                val report = verificationEngine.verifyPatch(
                    patchName = patch.name ?: "Unnamed Patch",
                    targetClass = null,
                    targetMethod = null,
                    mutationsApplied = mutations
                )
                auditReports.add(report)
                if (report.verdict == VerificationVerdict.NO) {
                    logger.warn("Patch '${patch.name}': 0 mutations / 0 target modifications detected (VERDICT: NO)")
                } else if (report.verdict == VerificationVerdict.MAYBE) {
                    logger.warn("Patch '${patch.name}': Unverified / partial execution (VERDICT: MAYBE)")
                } else {
                    logger.info("Patch '${patch.name}': Modifications verified (VERDICT: YES)")
                }
            }

            val breakdown = verificationEngine.generateFinalBreakdown(auditReports)
            for (line in breakdown.lines()) {
                if (line.isNotBlank()) {
                    if (totalModifiedFiles == 0 || line.contains("VERDICT: NO") || line.contains("Warning") || line.contains("ZERO EFFECT")) {
                        logger.warn(line)
                    } else {
                        logger.info(line)
                    }
                }
            }
        } catch (e: Exception) {
            logger.warn("Reachability indexing encountered an issue: ${e.message}")
        }
        listener.stepCompleted() // Saving
    }

    override fun close() {
        tempDir.deleteRecursively()
        // A patch that loads a native library from the workspace marks its directory read-only for Android 15+ W^X
        fileWorkspace.walkTopDown().forEach { it.setWritable(true) }
        fileWorkspace.deleteRecursively()
        patcher.close()
    }

    companion object {
        operator fun PatchResult.component1() = patch
        operator fun PatchResult.component2() = exception
    }
}
