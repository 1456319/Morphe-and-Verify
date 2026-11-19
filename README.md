# Morphe-and-Verify 🔍🛡️

> **Independent Fork Announcement & Non-Association Notice:**  
> **Morphe-and-Verify** is an independent, community-driven research and hardening fork developed by [@1456319](https://github.com/1456319).  
> **This project is NOT associated with, affiliated with, sponsored by, or endorsed by the original Morphe developers, MorpheApp organization, or ReVanced team.** All product and registered names remain the property of their respective owners.

---

## ⚠️ Important User Advisory: Why You Will See More "Failures" and "Warnings"

**Morphe-and-Verify does NOT apply patches less effectively than upstream Morphe. It applies the exact same patches using the exact same Dalvik bytecode mutation toolchain—but reports results TRUTHFULLY.**

In upstream Morphe (and classic ReVanced Manager), "Success" is defined purely as:
$$\text{Status} = \text{Success} \iff \text{The AST visitor executed without throwing an uncaught smali exception}$$

Under upstream's definition:
- If a universal privacy patch (e.g. *Block analytics & tracking SDKs*) scans 50,000 classes, finds **zero matching markers**, and modifies **zero bytecode instructions**, upstream enthusiastically logs `STATUS_SUCCESS` and shows a solid green checkmark: `[✓] Block analytics & tracking SDKs: Success`.
- If an AI-removal patch (e.g. *Disable AI*) forces a legacy getter to return `false`, but that method has **zero callers in any UI/ViewModel** and is **bypassed by compound boolean guards in the native app**, upstream reports `[✓] Disable AI: Success`.

### What to Expect in Morphe-and-Verify
Users switching to **Morphe-and-Verify** can expect a **frustratingly higher rate of `[⚠️] PARTIAL SUCCESS (MAYBE)` and `[✗] ZERO MUTATIONS (NO)` reports**.

> **These are NOT failures of this fork to apply patches.**  
> They are an honest, transparent diagnostic revealing that the underlying third-party patches have always been silent placebos. When an ad-blocker fails, you visibly see an ad. When a telemetry patch fails, it fails silently in background threads. **Morphe-and-Verify ends the era of the privacy placebo.**

---

## 🎯 The Three Verification Pillars

To eliminate false success reporting, **Morphe-and-Verify** integrates the reverse-engineering toolchain from [MP-Manager](https://github.com/1456319/MP-Manager) (streaming multi-DEX reachability indexing, string-to-method caller tracing, and transport sinkholing) into three mandatory verification pillars:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ PILLAR 1: Physical Mutation Tracking ("Did the app patch anything?")        │
│   • Tracks physical bytecode changes: instructions replaced, inserted, NOPed.│
│   • Assertion: mutationsCount > 0.                                           │
│   • If mutations == 0 => (NO): ZERO_MUTATIONS_PLACEBO. Never marked success. │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ PILLAR 2: Multi-DEX Caller Reachability ("Did the matched method have callers?")
│   • Streaming DexReachabilityEngine indexes invocation opcodes across all DEX│
│     files without heap exhaustion.                                           │
│   • Distinguishes active UI/ViewModels from dead/orphaned code.              │
│   • If mutations > 0 but callers == 0 => (MAYBE): DEAD_CODE_PATCH.           │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ PILLAR 2.5: Complex Heuristic Verification (Compound Guards & Fallbacks)     │
│   • Compound Guard Detection: Inspects caller bytecode for boolean negations │
│     (e.g., if (!getXfinityAssistant() && !getCoam()) {...}). A secondary     │
│     condition evaluating to true negates the patch at runtime.               │
│   • Sibling Telemetry Scan: Detects unpatched parallel tracking SDKs (Sift,  │
│     Datadog, Splunk, Branch) operating alongside stubbed targets.            │
│   • Domain Residual Scan: Verifies whether tracker endpoints persist in DEX. │
└──────────────────────────────────────┬───────────────────────────────────────┘
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│ PILLAR 3: Truthful Multi-Tier Final Report                                   │
│   • Per-patch verdict: (YES) / (NO) / (MAYBE) with heuristic justifications. │
│   • Concluding Verdict:                                                      │
│     "Have ALL modifications been successfully applied in a way that's        │
│      likely to have the intended effect?"                                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔬 Empirical Case Study: Xfinity App (`com.xfinity.digitalhome`)

During audit benchmarks on real target binaries (`stock.apk` vs. `xfinity_base.apk`), our engine exposed why upstream's reports are misleading:

| Patch | Upstream Morphe Report | Morphe-and-Verify Verdict | Verified Reality in Bytecode |
| :--- | :---: | :---: | :--- |
| **Block analytics & tracking SDKs** *(Proteus)* | `[✓] Success` | **(NO)** | **0 calls matched, 0 instructions modified.** Standard markers (`com/google/firebase/analytics`) were absent. Completely placebo. |
| **Block advertising & device IDs** *(Proteus)* | `[✓] Success` | **(NO)** | **0 calls matched, 0 instructions modified.** Getters were not directly queried. |
| **Disable AI** *(semicoloncolonel)* | `[✓] Success` | **(MAYBE)** | **1 instruction rewritten, 1 legacy caller.** The caller (`DefaultXfinityAssistant.start`) has a compound condition: `!getXfinityAssistantEnabled() && !getCoamActivationEnabled()`. Because `getCoamActivationEnabled()` is `true`, `true && false` evaluates to `false`. **The abort branch never runs; the AI launches unhindered.** |
| **Block analytics & tracking** *(semicoloncolonel)* | `[✓] Success` | **(MAYBE)** | **Wrapper methods stubbed**, but **73 proprietary Comcast Sift calls** and **23 Comcast AIQ telemetry calls** remain active in bytecode. |

---

## 🛠️ Features Carried Over from Upstream

Morphe-and-Verify preserves 100% of the operational capabilities of standard Morphe:
- **Full Compatibility:** Works with existing Morphe and ReVanced patch bundles, custom patch sources, and repositories.
- **Root & Non-Root Support:** Standard APK re-signing or Magisk/Zygisk root mount installation.
- **Simple & Expert Modes:** Quick one-tap patching or granular per-patch configuration with live memory and progress tracking.
- **Split APK & Architecture Optimization:** Native library stripping and locale/density filtering.
- **Shizuku & Direct Installers:** One-tap background installation without prompt spam.

---

## 📄 License & Attribution

- **Morphe-and-Verify** is licensed under the [GNU General Public License v3.0](LICENSE).
- Based on foundational work by [MorpheApp/morphe-manager](https://github.com/MorpheApp/morphe-manager), [ReVanced](https://github.com/ReVanced/revanced-manager), and [URV](https://github.com/Jman-Github/Universal-ReVanced-Manager).
- All reverse-engineering reachability modules, caller tracing engines, and heuristic validators are contributed under GPLv3 by [@1456319](https://github.com/1456319).
