# MaigBind

**Hardware-backed biometric transaction signing, device key binding, and server-side attestation verification for Android, JVM backends, and Kotlin Multiplatform.**

Maven group: `io.github.maignardi` · License: [Apache 2.0](LICENSE)

---

## Why MaigBind Exists

Calling `BiometricPrompt.authenticate(promptInfo)` **without** a `CryptoObject` and branching locally on `onAuthenticationSucceeded` provides **zero cryptographic assurance**:

- A one-line Frida hook (e.g., WithSecure/F-Secure *Universal Android Biometric Bypass*) can invoke `onAuthenticationSucceeded` directly.
- Any local `if (authenticated)` check can be bypassed in bytecode.
- An attacker can replay captured HTTP calls from a script without ever touching biometric hardware.

MaigBind replaces that pattern with an end-to-end cryptographic protocol:

> **The server executes a sensitive operation only if it carries a valid ECDSA P-256 signature computed by a non-exportable hardware key (StrongBox / TEE / Secure Enclave), unlocked by strong biometrics for that exact invocation, over the deterministic canonical CBOR bytes of the exact transaction.**

---

## Modules

| Module | Platform | Description |
|---|---|---|
| `maigbind-core` | KMP (`commonMain`: Android, JVM, iOS) | Protocol models, RFC 8949 §4.2 Deterministic CBOR, domain separation tags, Base64url, SHA-256, typed `MaigBindError` |
| `maigbind-android` | Android (`minSdk 24`) | StrongBox/TEE P-256 Keystore generation, `BiometricPrompt` (`BIOMETRIC_STRONG` + `CryptoObject` reference identity verification), suspend API |
| `maigbind-verifier` | JVM (Java 17+) | Dual-root Google PKIX validation (Legacy RSA + Apr 2026 RKP ECDSA P-384), CRL revocation (`/attestation/status`), OID `1.3.6.1.4.1.11129.2.1.17` inspection, immediate PoP, `NonceStore`, `VerificationPolicy` |
| `maigbind-ios` | KMP iOS (Phase 2 interface) | `Secure Enclave` (`[.privateKeyUsage, .biometryCurrentSet]`) + `LAContext` + `DCAppAttestService` interface |
| `sample-server` | JVM (Ktor 3) | Reference backend implementing `/enroll/*` and `/tx/*` with step-up MFA gating |
| `sample-app` | Android (Jetpack Compose) | Demo banking app exercising enrollment, StrongBox/TEE reporting, transfers, and re-enrollment |
| `attack-suite` | Frida + JUnit | Automated threat tests and Frida PoC scripts ([attack-suite/README.md](attack-suite/README.md)) |

---

## Quickstart

### 1. Dependencies

```kotlin
// Android app
dependencies {
    implementation("io.github.maignardi:maigbind-android:<version>")
}

// JVM backend
dependencies {
    implementation("io.github.maignardi:maigbind-verifier:<version>")
}
```

### 2. Server Integration (`maigbind-verifier`)

#### Configure `MaigBindVerifier` (with Redis `NonceStore`)

```kotlin
val redisAdapter = object : RedisCommands {
    override fun setWithTtlMillis(key: String, value: String, ttlMillis: Long): Boolean {
        // e.g. jedis.psetex(key, ttlMillis, value) == "OK"
        return jedisPool.resource.use { it.psetex(key, ttlMillis, value) == "OK" }
    }

    override fun getAndDelete(key: String): String? {
        // Redis 6.2+ atomic GETDEL (or Lua GET + DEL)
        return jedisPool.resource.use { it.getDel(key) }
    }
}

val verifier = MaigBindVerifier(
    policy = VerificationPolicy(
        requireStrongBox = false,           // true to enforce dedicated StrongBox HSM
        minOsPatchLevel = 202501,           // YYYYMM minimum hardware-enforced patch level
        allowFactoryKeys = true,            // false to require RKP ECDSA P-384 chains only
        allowWeakBiometricOptIn = false,    // always reject BIOMETRIC_WEAK unless opted in
        expectedApps = listOf(
            ExpectedAndroidApp.fromHexDigests(
                packageName = "com.example.bank",
                "10:39:38:EC:...",          // SHA-256 of your release signing certificate
            ),
        ),
        failMode = FailMode.FAIL_CLOSED,    // reject on Google CRL/root feed outage
        keyboxSuspicionThreshold = 50,      // flag shared batch CAs across >= 50 accounts
    ),
    nonceStore = RedisNonceStore(redisAdapter),
)
```

#### Handle Enrollment (2 Steps) & Transaction Verification

```kotlin
// Step 0: ONLY after verifying step-up MFA / eKYC on the user session!
val challenge = verifier.beginEnrollment(accountId = user.id, ttlSeconds = 120)

// Step 1: Verify X.509 attestation chain -> stores PENDING_POP binding & returns popChallenge
val attestResp = verifier.verifyEnrollmentAttestation(enrollmentRequest)
if (!attestResp.verdict.isVerified) {
    // Inspect attestResp.verdict.status (REJECTED_POLICY, REJECTED_FRAUD_SIGNAL, ERROR_VALIDATION_INFRA)
    // and attestResp.verdict.findings (FindingCode + severity)
    return forbid(attestResp.verdict)
}

// Step 2: Verify immediate biometric Proof-of-Possession -> transitions binding to ACTIVE
val confirmResp = verifier.confirmEnrollmentPop(confirmRequest)
check(confirmResp.status == EnrollmentStatus.ACTIVE)

// Transaction Step A: Issue single-use nonce bound to active keyId
val txChallenge = verifier.issueTransactionNonce(accountId = user.id, keyId = keyId, ttlSeconds = 90)

// Transaction Step B: Verify signature + nonce + field-by-field parity with server business command
val verdict = verifier.verifyTransaction(
    accountId = user.id,
    signedPayload = request.signedPayload,
    expectedOperationType = "PIX_TRANSFER",
    expectedFields = canonicalFields(
        "amountCents" to canonical(command.amountCents), // extracted from server command, NOT trusted blindly
        "currency" to canonical(command.currency),
        "recipient" to canonical(command.recipient),
    ),
)

when (verdict.status) {
    VerdictStatus.VERIFIED -> executeTransfer(command)
    VerdictStatus.REJECTED_POLICY,
    VerdictStatus.REJECTED_FRAUD_SIGNAL -> rejectAndAudit(verdict.findings)
    VerdictStatus.ERROR_VALIDATION_INFRA -> returnServiceUnavailable(verdict.findings)
}
```

### 3. Android Client Integration (`maigbind-android`)

```kotlin
val maigBind = MaigBind(
    context = applicationContext,
    config = MaigBindConfig(
        preferStrongBox = true,                     // try StrongBox, fall back to TEE
        requireStrongBox = false,                   // set true to reject TEE-only devices
        includeDevicePropertiesAttestation = false, // optional Device ID attestation (API 31+)
        allowWeakBiometricFallback = false,         // strict BIOMETRIC_STRONG only
    ),
)

// Check device readiness before showing biometric actions
when (maigBind.getBiometricCapability()) {
    BiometricCapability.READY_STRONG -> { /* ready */ }
    BiometricCapability.NONE_ENROLLED -> { /* prompt user to enroll fingerprint/face in Settings */ }
    else -> { /* show fallback / unsupported UX */ }
}

// Enrollment Step 1: Generate hardware key + collect attestation chain
val enrollReq = when (val res = maigBind.enroll(accountId, beginResp.challengeBase64Url)) {
    is MaigBindResult.Success -> res.value
    is MaigBindResult.Failure -> return handleMaigBindError(res.error)
}
val attestResp = api.postEnrollAttest(enrollReq)

// Enrollment Step 2: Immediate biometric Proof-of-Possession
val popReq = when (
    val res = maigBind.confirmEnrollmentPop(
        activity = fragmentActivity,
        bindingId = attestResp.bindingId,
        accountId = accountId,
        popChallengeBase64Url = attestResp.popChallengeBase64Url,
        issuedAt = System.currentTimeMillis(),
        expiresAt = attestResp.popExpiresAt,
        promptText = PromptText(
            title = "Bind This Device",
            subtitle = "Confirm with biometrics to activate hardware key",
        ),
    )
) {
    is MaigBindResult.Success -> res.value
    is MaigBindResult.Failure -> return handleMaigBindError(res.error)
}
api.postEnrollConfirm(popReq)

// Signing a sensitive operation
val keyId = maigBind.getEnrolledKeyId(accountId) ?: return startEnrollment()
val payload = TransactionPayload(
    keyId = keyId,
    operationType = "PIX_TRANSFER",
    nonce = serverNonce.nonceBase64Url,
    issuedAt = serverNonce.issuedAt,
    expiresAt = serverNonce.expiresAt,
    fields = canonicalFields(
        "amountCents" to canonical(150_000L),
        "currency" to canonical("BRL"),
        "recipient" to canonical("alice@bank.example"),
    ),
)

when (
    val res = maigBind.sign(
        activity = fragmentActivity,
        accountId = accountId,
        payload = payload,
        promptText = PromptText(
            title = "Confirm PIX Transfer",
            subtitle = "BRL 1,500.00 to alice@bank.example",
            description = "Hardware-backed signature required",
        ),
    )
) {
    is MaigBindResult.Success -> api.postExecuteTransfer(res.value)
    is MaigBindResult.Failure -> handleMaigBindError(res.error)
}
```

#### Exhaustive Typed Error Handling

```kotlin
fun handleMaigBindError(error: MaigBindError) {
    when (error) {
        is MaigBindError.NeedsReEnrollment -> {
            // New fingerprint/face was enrolled on the device -> KeyPermanentlyInvalidatedException
            // Route user through authenticated step-up re-enrollment.
        }
        is MaigBindError.NotEnrolled -> startStepUpEnrollment()
        is MaigBindError.BiometryNotEnrolled -> promptSystemBiometricEnrollment()
        is MaigBindError.BiometryUnavailable -> showUnsupportedDeviceMessage()
        is MaigBindError.Lockout -> showLockoutMessage(permanent = error.isPermanent)
        is MaigBindError.Cancelled -> { /* user dismissed prompt */ }
        is MaigBindError.UserNotAuthenticated -> showRetryPrompt()
        is MaigBindError.CryptoObjectTampered -> abortAndReportSecurityTelemetry()
        is MaigBindError.HardwareUnavailable -> showHardwareUnavailableMessage()
        is MaigBindError.InvalidInput,
        is MaigBindError.PlatformFailure -> showGenericError(error.message)
    }
}
```

---

## Migration Guide: From `BiometricPrompt` Without `CryptoObject`

### Before (Insecure)

```kotlin
// VULNERABLE: Bypassable with a 5-line Frida hook on onAuthenticationSucceeded
val prompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
        api.executeTransfer(recipient, amount) // No hardware signature!
    }
})
prompt.authenticate(promptInfo)
```

### After (MaigBind)

```kotlin
// SECURE: Server verifies hardware ECDSA signature bound to biometrics & exact canonical payload
val payload = TransactionPayload(
    keyId = keyId,
    operationType = "PIX_TRANSFER",
    nonce = serverNonce,
    issuedAt = issuedAt,
    expiresAt = expiresAt,
    fields = canonicalFields(
        "amountCents" to canonical(amountCents),
        "currency" to canonical("BRL"),
        "recipient" to canonical(recipient),
    ),
)
when (val res = maigBind.sign(activity, accountId, payload, promptText)) {
    is MaigBindResult.Success -> api.executeSignedTransfer(recipient, amountCents, res.value)
    is MaigBindResult.Failure -> handleMaigBindError(res.error)
}
```

---

## Threat Model Summary

See [THREAT_MODEL.md](THREAT_MODEL.md) and [PROTOCOL.md](PROTOCOL.md) for the complete analysis and Mermaid sequence diagrams.

- **Frida callback hooking:** Pre-initialized `Signature.initSign(privateKey)` + strict reference identity `result.cryptoObject?.signature === signature` + hardware biometric `AuthToken` requirement.
- **Root + leaked keyboxes / TrickyStore:** Google CRL checks (`https://android.googleapis.com/attestation/status`), `hardwareEnforced` `rootOfTrust` validation, RKP ECDSA P-384 root policy, and intermediate batch keybox fan-out heuristics.
- **Quarkslab Attestation Relay (Aug 2026):** One-shot relay is blocked by `attestationApplicationId` (Tag 709) + immediate biometric Proof-of-Possession before binding activation + per-transaction PoP.

---

## What MaigBind Does NOT Protect Against

No mobile client library is unbypassable. Integrators must understand these residual risks:

1. **Enrollment Hijacking:** If an attacker compromises a victim's session/credentials and enrolls **their own clean device**, that device passes hardware attestation. **You MUST gate `beginEnrollment` behind strong step-up authentication (MFA, eKYC, or out-of-band approval) and send out-of-band binding alerts.**
2. **Unrevoked Private Leaked Keyboxes:** If an attacker uses a leaked OEM factory keybox not yet listed in `/attestation/status`, attestation cryptography alone cannot distinguish it from a real device.
3. **Interactive Online Signing Proxies:** If an attacker physically controls a clean device running the genuine app and personally provides biometrics on it while proxying traffic, cryptography cannot distinguish remote proxying from local use. Mitigate with IP/ASN/risk telemetry.
4. **Pre-Signature Accessibility / Overlay Malware:** Google deprecated/abandoned broad adoption of Android Protected Confirmation (`ConfirmationPrompt`), so `BiometricPrompt.PromptInfo` text is OS-rendered rather than TEE-rendered. Malware with `AccessibilityService` or memory injection could alter UI inputs *before* `TransactionPayload` is constructed.

> **Recommendation:** Pair MaigBind with **Google Play Integrity API** (server-side verdict) during enrollment and high-risk operations as an additional defense-in-depth signal — never as a replacement for hardware key binding.

---

## Running Tests, Demo Apps & Attack Suite

```bash
# Run lint, static analysis, and unit tests across all modules
./gradlew ktlintCheck detekt :maigbind-core:jvmTest :maigbind-core:testAndroidHostTest :maigbind-verifier:test :maigbind-android:testDebugUnitTest :sample-server:test :sample-app:testDebugUnitTest

# Run Android instrumented tests (requires connected device/emulator with BIOMETRIC_STRONG enrolled)
./gradlew :maigbind-android:connectedDebugAndroidTest

# Start the sample Ktor backend on http://localhost:8080
./gradlew :sample-server:run

# Install the Jetpack Compose demo app onto an Android emulator (connects to http://10.0.2.2:8080)
./gradlew :sample-app:installDebug

# Generate Dokka API documentation
./gradlew :maigbind-core:dokkaGeneratePublicationHtml :maigbind-verifier:dokkaGeneratePublicationHtml :maigbind-android:dokkaGeneratePublicationHtml
```

See [attack-suite/README.md](attack-suite/README.md) for the Frida PoC scripts (`bypass_biometric_callback.js`, `attestation_relay_hook.js`) and threat-to-test mapping.
