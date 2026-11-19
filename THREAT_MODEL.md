# MaigBind Threat Model

> **Project:** MaigBind (`io.github.maignardi`) — Apache 2.0  
> **Scope:** Hardware-backed, biometric-bound cryptographic transaction signing and device binding protocol for Android (Phase 1), JVM Server Verifier, and iOS (Phase 2).

---

## 1. Security Objective & Core Invariant

Most mobile apps implement biometrics by calling `BiometricPrompt.authenticate(promptInfo)` without a `CryptoObject` and executing an `if (succeeded)` branch on the client. That pattern provides **zero cryptographic assurance**: an attacker with Frida, Xposed, or a patched APK can invoke `onAuthenticationSucceeded` directly, or replay network requests from outside the device.

MaigBind enforces a single end-to-end invariant:

> **The server accepts a sensitive operation if and only if it carries a valid signature produced by a non-exportable private key, generated inside secure hardware, bound to the genuine application and enrolled account, unlocked by strong biometrics for that exact invocation, over the exact canonical bytes of the operation being executed.**

### Honesty Principle: What No Client Library Can Guarantee

No client-side mobile library is unbypassable. An attacker who controls the OS kernel, runtime memory, or physical device with an unlocked user session can still attempt runtime manipulation or social engineering. Therefore, this document explicitly separates:

1. **Mitigated threats** (cryptographically prevented or rejected by the server).
2. **Threats made substantially more expensive or detectable** (raised from trivial one-liner Frida scripts to multi-device/online-proxy/kernel-level compromises).
3. **Out-of-scope / Integrator & Backend responsibilities** (controls the host application and backend **must** implement alongside MaigBind).

---

## 2. Trust Boundaries & Assumptions

| Component | Trust Level | Notes |
|---|---|---|
| **Android KeyMint / Keymaster (TEE / StrongBox)** & **iOS Secure Enclave** | **Trusted Hardware** | Generates non-exportable P-256 keys, enforces biometric AuthToken verification before signing, and signs key attestation chains (unless OEM factory keybox is leaked and unrevoked). |
| **Android OS / App Process / JVM Runtime** | **Untrusted** | Treated as potentially rooted, instrumented (Frida), or running under an attacker's debugger. No authorization decision is made on the client. |
| **Network Transport** | **Untrusted (TLS assumed, not relied upon for payload integrity)** | TLS protects confidentiality in transit, while MaigBind signatures provide end-to-end payload integrity and non-repudiation of key possession. |
| **Backend (`maigbind-verifier` + Integrator API)** | **Trusted** | Generates challenges/nonces, verifies Google/Apple attestation chains and CRLs, verifies ECDSA signatures, compares signed payloads against executed business commands, and enforces policy. |

---

## 3. Threat Analysis

### T1. Runtime Hooking of `BiometricPrompt` Callback (Frida / Xposed)

- **Attack:** Public scripts (e.g., WithSecure/F-Secure *Universal Android Biometric Bypass*) hook `BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded` and pass a forged `AuthenticationResult` with a `null` `CryptoObject`, or a `CryptoObject` wrapping an attacker-controlled or unauthenticated `Signature` instance.
- **MaigBind Mitigation:**
  1. `Signature.initSign(privateKey)` is called **before** `BiometricPrompt.authenticate(promptInfo, CryptoObject(signature))`.
  2. Inside `onAuthenticationSucceeded(result)`, MaigBind validates that `result.cryptoObject` is non-null **and** that `result.cryptoObject?.signature === expectedSignature` (strict reference identity `===`) as **client-side defense-in-depth** to fail fast on simple callback hooks. (An attacker with Frida can also hook that reference comparison in bytecode/memory.)
  3. **Authoritative Mitigation (Server-Side):** `signature.update(signingInput)` and `signature.sign()` execute inside the callback. Because the Keystore key was created with `setUserAuthenticationRequired(true)`, `AUTH_BIOMETRIC_STRONG`, and `timeout = 0`, KeyMint/Keymaster refuses to compute the ECDSA signature unless the biometric HAL minted a valid hardware HMAC `AuthToken` for that exact operation handle. Even if an attacker hooks the client check or swaps in a software key, the forged signature fails server-side ECDSA verification against the hardware-attested public key stored during enrollment.
- **Status:** **Mitigated** (by hardware KeyMint AuthToken + server-side ECDSA verification).

---

### T2. Client-Side Authorization Bypass (`if (success)`)

- **Attack:** Attacker patches bytecode (`smali`), hooks Kotlin methods, or flips boolean flags so the client treats a failed/skipped biometric check as approved.
- **MaigBind Mitigation:** MaigBind exposes **no boolean "isAuthenticated" authorization API**. The client returns a `SignedPayload` containing the canonical payload and DER ECDSA signature. The client never approves a transaction; `maigbind-verifier` on the server is the sole authority.
- **Status:** **Mitigated.**

---

### T3. Rooted Device + Leaked Keybox / TrickyStore / Bootloader Spoofing

- **Attack:** On a rooted device with an unlocked bootloader, tools such as TrickyStore inject a leaked OEM/factory attestation keybox to forge a genuine-looking Google-signed certificate chain reporting `verifiedBootState = VERIFIED` and `deviceLocked = true`.
- **MaigBind Mitigation:**
  1. **Real-time Revocation Checks:** `maigbind-verifier` fetches and caches `https://android.googleapis.com/attestation/status` (configurable TTL) and rejects any certificate chain whose serial appears with `REVOKED` or `SUSPENDED`. This immediately neutralizes known leaked keyboxes.
  2. **Strict `hardwareEnforced` Inspection:** All security-critical tags (`rootOfTrust.verifiedBootState == VERIFIED`, `rootOfTrust.deviceLocked == true`, `purpose`, `algorithm`, `ecCurve`, `userAuthType`, `authTimeout`, `osPatchLevel`) are read exclusively from `hardwareEnforced` (never `softwareEnforced`), and `attestationSecurityLevel` / `keymasterSecurityLevel` must be `TRUSTED_ENVIRONMENT` or `STRONG_BOX` (never `SOFTWARE`).
  3. **RKP vs. Factory Key Policy:** After Android's April 10, 2026 RKP root cutover (ECDSA P-384, rolled out Feb 2026), `VerificationPolicy` allows servers to restrict or flag legacy factory-keyed chains (`allowFactoryKeys = false` for high-assurance tiers).
  4. **Experimental Keybox Velocity Telemetry:** `maigbind-verifier` optionally tracks distinct accounts per leaf-adjacent batch certificate within a short sliding window (`keyboxSuspicionThreshold`, default 1,000 accounts / 10 min, `rejectOnSuspiciousKeybox = false`). Because Google legitimately shares factory batch certificates across ~100,000+ handsets, this heuristic is **experimental telemetry only** and should not be used alone for hard blocking.
- **Residual Risk (Honest Assessment):** If an attacker possesses a *private, unrevoked* leaked factory keybox not yet listed in Google's status endpoint, cryptographic attestation verification alone cannot distinguish it from a genuine factory device.
- **Status:** **Mitigated for revoked/software-spoofed keyboxes; Made Significantly Harder / Detectable for private unrevoked keyboxes.** Combine with Google **Play Integrity API** (server-side verdict) and backend risk signals.

---

### T4. Attestation Relay (Quarkslab, August 11, 2026)

- **Attack:** As demonstrated by Eric Le Guevel / Quarkslab (*"Bypassing Android Hardware Attestation from the Analyst's Chair"*, August 11, 2026, `android-hardware-attestation-demo`), Frida hooks the key-generation/attestation code in the target app on a rooted device, forwards the server's `attestationChallenge` over the network to a clean, locked "oracle" device running a custom attestation helper app, and relays the genuine certificate chain back to the server.
- **Why Naive Implementations Fail:** Key attestation proves that *some* healthy secure hardware generated a key for that challenge — **not** that the key resides on *this* physical device, *this* process, or *this* active session.
- **MaigBind Mitigation (Defense-in-Depth):**
  1. **App Identity Binding (`attestationApplicationId`, Tag 709):** `maigbind-verifier` verifies that the package name and SHA-256 signing certificate digest in Tag 709 match the genuine app. This blocks a generic third-party "oracle app" on the clean device; the attacker would have to run the genuine banking app itself on the clean device. (Tag 709 is in `softwareEnforced`, so MaigBind trusts it **only** when `hardwareEnforced` `rootOfTrust` proves `VERIFIED` + `deviceLocked == true`.)
  2. **Immediate Proof-of-Possession (PoP) at Enrollment:** After validating the attestation chain for challenge $C_1$, the server does **not** activate the key yet. It issues a short-lived `popChallenge` ($C_2$) that the client must sign with the newly generated private key **via Strong Biometrics (`BiometricPrompt` + `CryptoObject`)** before transitioning the binding from `PENDING_POP` to `ACTIVE`.
  3. **Continuous Per-Transaction PoP:** Every subsequent sensitive operation requires a fresh biometric-unlocked ECDSA signature from that exact private key. This converts a one-shot enrollment relay into a persistent, interactive **online signing proxy** where the genuine app on a clean device must remain online and receive live biometric approvals for every operation.
- **Residual Risk (Honest Assessment):** If an attacker physically controls a clean locked device running the genuine app and uses it as an interactive remote signing oracle (providing biometrics on the clean device while driving the UI from an instrumented device), pure cryptography cannot distinguish a remote proxy from local execution.
- **Status:** **One-shot relay Mitigated; Continuous online proxy Made Substantially More Expensive & Operationally Constrained.** Mitigate further with Play Integrity API, IP/ASN correlation, and session telemetry.

---

### T5. Signature Replay

- **Attack:** Attacker captures a valid `SignedPayload` from a previous transaction (via MITM proxy, device logs, or compromised storage) and replays it to execute the operation again.
- **MaigBind Mitigation:**
  1. Every `TransactionPayload` embeds a server-generated CSPRNG `nonce` (minimum 128 bits), `issuedAt`, and short-lived `expiresAt`.
  2. `maigbind-verifier` enforces atomic single-use consumption via a pluggable `NonceStore` (`consumeIfUnused`) and rejects expired or future-dated payloads beyond configured clock skew.
  3. The `keyId` inside the signed payload binds the signature to the exact enrolled key.
- **Status:** **Mitigated.**

---

### T6. Post-Signature Tampering & Banking Trojan (Accessibility / Overlay / MITB)

- **Attack:** Malware with `AccessibilityService` or network interception alters the destination account or amount *after* the user signs, or tricks the user into signing a modified request.
- **MaigBind Mitigation:**
  1. All operation fields (`operationType`, `amount`, `currency`, `recipient`, etc.) plus `nonce`, `issuedAt`, `expiresAt`, `keyId`, and `protocolVersion` are serialized with **RFC 8949 §4.2 Deterministic CBOR** and prefixed with domain tag `"MaigBind/v1/tx\0"` prior to signing.
  2. On the server, `maigbind-verifier` verifies the signature over the exact canonical bytes **and** performs a strict field-by-field comparison between the verified `TransactionPayload` and the business command the backend is about to execute. Any discrepancy fails closed.
  3. MaigBind displays a human-readable transaction summary in `BiometricPrompt.PromptInfo` (`title`, `subtitle`, `description`).
- **Residual Risk (Honest Assessment):** Google deprecated/abandoned broad adoption of **Android Protected Confirmation** (`ConfirmationPrompt` trusted UI), so MaigBind intentionally does **not** depend on it. Because `BiometricPrompt` UI strings are supplied by the app process (not a TEE-rendered trusted display), malware with full memory access or Accessibility privileges *prior* to signing could alter the amount/recipient before `PromptInfo` and payload creation, or overlay the screen to deceive the user.
- **Status:** **Post-signature tampering Mitigated; Pre-signature Accessibility deception is Residual Risk** (host app should employ Accessibility abuse detection, overlay protection `FILTER_TOUCHES_WHEN_OBSCURED`, and out-of-band confirmation for high-risk thresholds).

---

### T7. Unauthorized Biometric Enrollment on Unlocked Device

- **Attack:** Attacker steals or briefly accesses an unlocked device (knowing or bypassing the lock screen PIN) and adds their own fingerprint/face in Android/iOS Settings so they can authorize banking transactions.
- **MaigBind Mitigation:**
  1. Android keys are generated with `setInvalidatedByBiometricEnrollment(true)`. Adding a new biometric permanently invalidates the key in Keystore; subsequent `Signature.initSign()` throws `KeyPermanentlyInvalidatedException`, which MaigBind maps to `MaigBindError.NeedsReEnrollment`.
  2. Android keys (API 28+) set `setUnlockedDeviceRequired(true)` so keys cannot be used while the device is locked (with documented handling for Android 12–14 lock-screen-removal edge cases).
  3. Phase 2 iOS keys use `SecAccessControl` `[.privateKeyUsage, .biometryCurrentSet]`, which provides identical invalidation semantics on Touch ID / Face ID changes.
- **Status:** **Mitigated.** (Re-enrollment requires full authenticated step-up per T10.)

---

### T8. Security Downgrade (PIN/Password Fallback, `BIOMETRIC_WEAK`, Software Key)

- **Attack:** Attacker forces `BiometricPrompt` to fall back to weak biometrics (Class 2 face unlock), device PIN/pattern (`DEVICE_CREDENTIAL`), or forces key generation in software keystore rather than TEE/StrongBox.
- **MaigBind Mitigation:**
  1. **Client-Side Enforcement:** `KeyGenParameterSpec` configures `AUTH_BIOMETRIC_STRONG` with `timeout = 0` (API 30+) or `setUserAuthenticationValidityDurationSeconds(-1)` (API < 30). `BiometricPrompt` strictly enforces `BIOMETRIC_STRONG` only — Android throws `IllegalArgumentException` if `CryptoObject` is paired with `BIOMETRIC_WEAK` or `DEVICE_CREDENTIAL`, so weak/credential fallbacks are not supported.
  2. **Server-Side Enforcement (Authoritative):** `maigbind-verifier` never trusts unsigned client flags; it inspects the Google-signed attestation extension's `hardwareEnforced` list and rejects:
     - `attestationSecurityLevel` or `keymasterSecurityLevel == SOFTWARE`
     - Presence of `noAuthRequired`
     - `userAuthType` lacking biometric hardware (`HW_AUTH_BIOMETRIC`)
     - `authTimeout` present and `> 0`
     - Weak curves/algorithms (requires EC P-256, `PURPOSE_SIGN`).
- **Status:** **Mitigated.**

---

### T9. App Repackaging / Cloning

- **Attack:** Attacker decompiles the APK, modifies code, re-signs with their own debug/release certificate (or clones the app with a different package name), and tries to enroll keys against the production backend.
- **MaigBind Mitigation:**
  1. `maigbind-verifier` extracts `attestationApplicationId` (OID extension tag `[709]`) and verifies that both the **package name** and **SHA-256 signing certificate digest(s)** match the backend's allowlist (`VerificationPolicy.expectedApps`).
  2. Because tag `[709]` is populated in `softwareEnforced` by the Android framework (`keystore2`), `maigbind-verifier` enforces that `hardwareEnforced.rootOfTrust` reports `verifiedBootState == VERIFIED` and `deviceLocked == true` before trusting `attestationApplicationId`.
  3. On iOS (Phase 2), Apple's App Attest verifies `TeamID.BundleID` (`rpIdHash`) inside the Apple-signed attestation statement.
- **Status:** **Mitigated** (assuming locked verified bootloader; if bootloader is unlocked, `rootOfTrust` fails verification independently).

---

### T10. Enrollment Hijacking

- **Attack:** Attacker compromises a user's login credentials or session cookie, calls the enrollment endpoint from the **attacker's own clean device**, and binds the attacker's hardware key to the victim's account. From then on, the attacker holds a genuine hardware-bound credential for the victim's account.
- **MaigBind Mitigation & Responsibility Boundary:**
  - **MaigBind CANNOT prevent enrollment hijacking by itself**, because a clean device belonging to an attacker passes all hardware attestation checks!
  - **Mandatory Integrator / Backend Responsibility:**
    1. Gate `POST /enroll/begin` behind **strong step-up authentication** (MFA, SMS/email OTP + out-of-band confirmation, eKYC/liveness check, or approval from an existing bound device).
    2. Enforce **cooling-off windows** or transaction limits on newly enrolled bindings.
    3. Send out-of-band push/email/SMS notifications whenever a new `keyId` is bound or old bindings are revoked.
    4. Enforce `maxActiveBindingsPerAccount` (default `1` active binding per account, automatically revoking prior devices on re-enrollment) and expose `revokeBinding()` / `revokeAccountBindings()` for lost/stolen devices.
- **Status:** **Integrator / Backend Responsibility** (documented as a mandatory integration contract).

---

## 4. Summary Matrix

| ID | Threat | Outcome | Primary Defense |
|---|---|---|---|
| **T1** | Frida `BiometricPrompt` callback hook | **Mitigated** | Pre-init `Signature` + `CryptoObject` reference identity + hardware AuthToken |
| **T2** | Client `if (success)` bypass | **Mitigated** | Zero client authorization decisions; server-side ECDSA verification |
| **T3** | Root + leaked keybox / TrickyStore | **Mitigated (revoked) / Harder (unrevoked)** | Google CRL (`/attestation/status`), `hardwareEnforced` `rootOfTrust`, RKP policy, keybox heuristics |
| **T4** | Attestation relay (Quarkslab 2026) | **One-shot Mitigated / Proxy Harder** | Tag 709 app binding + immediate biometric PoP at enrollment + per-tx PoP |
| **T5** | Signature replay | **Mitigated** | Server CSPRNG `nonce`, short TTL, atomic `NonceStore` |
| **T6** | Post-signature tampering / Trojan | **Mitigated (post-sign) / Residual (pre-sign UI)** | Deterministic CBOR + domain tag + server field-by-field check |
| **T7** | New biometric enrolled on unlocked device | **Mitigated** | `setInvalidatedByBiometricEnrollment(true)` / `.biometryCurrentSet` |
| **T8** | Downgrade (PIN / `BIOMETRIC_WEAK` / SW key) | **Mitigated** | `AUTH_BIOMETRIC_STRONG` + `timeout=0` + server `hardwareEnforced` verification |
| **T9** | Repackaged / cloned app | **Mitigated** | Tag 709 (`packageName` + SHA-256 cert) gated by `verifiedBootState == VERIFIED` |
| **T10** | Enrollment hijacking | **Integrator Responsibility** | Step-up MFA / eKYC / cooling-off period / binding limits on backend |

---

## 5. Recommended Complementary Controls

MaigBind provides cryptographic key binding and biometric transaction signing. For production banking/fintech deployments, combine MaigBind with:

1. **Google Play Integrity API (Server-Side Verdict):** Correlate device integrity (`MEETS_STRONG_INTEGRITY` / `MEETS_DEVICE_INTEGRITY`) and app licensing with MaigBind enrollment as an independent signal (never as a replacement).
2. **Backend Fraud & Risk Engine:** Velocity checks, IP/ASN/geolocation anomalies, impossible travel, and keybox batch-certificate fan-out monitoring.
3. **Android Runtime Hardening:** `FLAG_SECURE` on sensitive screens, `filterTouchesWhenObscured = true`, Accessibility service risk telemetry, and R8 obfuscation.
