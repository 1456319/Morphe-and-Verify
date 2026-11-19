package app.morphe.manager.patcher.verification

/**
 * Tri-state verification verdict for patch application.
 */
enum class VerificationVerdict {
    /**
     * Patch targets matched, modifications applied (>0), incoming callers verified,
     * and no known bypass conditions detected.
     */
    YES,

    /**
     * Zero targets matched or zero bytecode instructions modified.
     * The patch had no physical effect on the binary.
     */
    NO,

    /**
     * Modifications were made, but static analysis detected risk factors:
     * zero incoming callers (dead code), compound boolean negation in caller control flow,
     * or active fallback telemetry/domains remaining unblocked.
     */
    MAYBE
}

data class CallerSite(
    val callerClass: String,
    val callerMethod: String,
    val targetDescriptor: String,
    val isUiOrViewModel: Boolean,
    val instructionIndex: Int
) {
    override fun toString(): String = "$callerClass->$callerMethod"
}

data class PatchAuditReport(
    val patchName: String,
    val verdict: VerificationVerdict,
    val mutationsCount: Int,
    val matchedTargets: List<String>,
    val callersFound: List<CallerSite>,
    val compoundGuardDetected: Boolean,
    val fallbackTelemetryDetected: List<String>,
    val residualDomainsFound: List<String>,
    val justification: String
)
