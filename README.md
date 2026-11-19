# MaigBind — Hardware-Backed Biometric Signing & Key Attestation Library

[![CI](https://github.com/Maignardi/MaigBind-Lib/actions/workflows/ci.yml/badge.svg)](https://github.com/Maignardi/MaigBind-Lib/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

**Hardware-backed biometric transaction signing, device key binding, and server-side Android Key Attestation verification for banking and fintech apps.**

Maven group: `io.github.maignardi` · License: [Apache 2.0](LICENSE)

---

## Why MaigBind Exists

Calling `BiometricPrompt.authenticate(promptInfo)` **without** a `CryptoObject` and branching locally on `onAuthenticationSucceeded` provides **zero cryptographic assurance**:

- A one-line Frida hook (e.g., WithSecure/F-Secure *Universal Android Biometric Bypass*) can invoke `onAuthenticationSucceeded` directly.
- Any local `if (authenticated)` check can be bypassed in bytecode.
- An attacker can replay captured HTTP calls from a script without ever touching biometric hardware.

MaigBind replaces that pattern with an end-to-end cryptographic protocol:

> **The server executes a sensitive operation only if it carries a valid ECDSA P-256 signature computed by a non-exportable hardware key (StrongBox / TEE), unlocked by strong biometrics (`BIOMETRIC_STRONG`) for that exact invocation, over the deterministic canonical CBOR bytes of the exact transaction.**

---

## Modules

| Module | Status | Platform | Description |
|---|---|---|---|
| `maigbind-core` | Implemented | KMP (`commonMain`: Android, JVM, iOS) | Protocol models, RFC 8949 §4.2 Deterministic CBOR, domain separation tags, Base64url, SHA-256, typed `MaigBindError` |
| `maigbind-android` | Implemented | Android (`minSdk 24`) | StrongBox/TEE P-256 Keystore generation (hashed non-PII aliases, staged re-enrollment), `BiometricPrompt` (`BIOMETRIC_STRONG` + `CryptoObject`), suspend API |
| `maigbind-verifier` | Implemented | JVM (Java 17+) | Dual-root Google PKIX validation (Legacy RSA + Apr 2026 RKP ECDSA P-384), CRL revocation (`/attestation/status`), OID `1.3.6.1.4.1.11129.2.1.17` inspection, immediate PoP, binding revocation, `NonceStore`, `VerificationPolicy` |
| `maigbind-ios` | **Planned (Interface Only)** | KMP iOS (Phase 2) | Contract only (`MaigBindIos` interface); Swift/Objective-C `Secure Enclave` + `LAContext` + `DCAppAttestService` implementation planned for v0.3 |
| `sample-server` | Implemented | JVM (Ktor 3) | Reference backend implementing `/enroll/*`, `/tx/*`, and `/bindings/revoke` with step-up MFA gating |
| `sample-app` | Implemented | Android (Jetpack Compose) | Demo banking app exercising staged enrollment, StrongBox/TEE reporting, transfers, and error handling |
| `attack-suite` | Implemented | Frida + JUnit | Automated threat tests and Frida PoC scripts ([attack-suite/README.md](attack-suite/README.md)) |

---

## Quickstart

### 1. Dependencies

> **Publishing note:** Maven Central publication under `io.github.maignardi` is configured via `vanniktech-maven-publish` (`0.2.0-SNAPSHOT`). Until the first Maven Central release tag is published, install locally with `./gradlew publishToMavenLocal` and enable `mavenLocal()`.

```kotlin
// settings.gradle.kts / repositories
repositories {
    mavenLocal() // while using 0.2.0-SNAPSHOT
    google()
    mavenCentral()
}

// Android app
dependencies {
    implementation("io.github.maignardi:maigbind-android:0.2.0-SNAPSHOT")
}

// JVM backend
dependencies {
    implementation("io.github.maignardi:maigbind-verifier:0.2.0-SNAPSHOT")
}
```

### 2. Server Integration (`maigbind-verifier`)

#### Configure `MaigBindVerifier` (with Redis `NonceStore`)

```kotlin
val redisAdapter = object : RedisCommands {
    override fun setWithTtlMillis(key: String, value: String, ttlMillis: Long): Boolean {
        return jedisPool.resource.use { it.psetex(key, ttlMillis, value) == "OK" }
    }

    override fun getAndDelete(key: String): String? {
        return jedisPool.resource.use { it.getDel(key) } // Redis 6.2+ atomic GETDEL
    }
}

val verifier = MaigBindVerifier(
    policy = VerificationPolicy(
        requireStrongBox = false,             // true to enforce dedicated StrongBox HSM
        minOsPatchLevel = 202501,             // YYYYMM minimum hardware-enforced patch level
        allowFactoryKeys = true,              // false to require RKP ECDSA P-384 chains only
        maxActiveBindingsPerAccount = 1,      // auto-revokes older bindings on re-enrollment
        expectedApps = listOf(
            ExpectedAndroidApp.fromHexDigests(
                packageName = "com.example.bank",
                "10:39:38:EC:...",            // SHA-256 of your release signing certificate
            ),
        ),
        failMode = FailMode.FAIL_CLOSED,      // reject on Google CRL/root feed outage
    ),
    nonceStore = RedisNonceStore(redisAdapter),
)
```

> **Experimental telemetry note:** `VerificationPolicy` also includes `keyboxSuspicionThreshold` (default `1,000` accounts within `10` minutes, `rejectOnSuspiciousKeybox = false`) to monitor burst fan-out on a leaf-adjacent factory batch certificate. Because Google legitimately shares factory batch certificates across ~100,000+ handsets, treat this strictly as experimental telemetry rather than a standalone blocking rule.

#### Handle Enrollment, Binding Revocation & Transaction Verification

```kotlin
// Step 0: ONLY after verifying step-up MFA / eKYC on the user session!
val challenge = verifier.beginEnrollment(accountId = user.id, ttlSeconds = 120)

// Step 1: Verify X.509 attestation chain -> stores PENDING_POP binding & returns popChallenge
val attestResp = verifier.verifyEnrollmentAttestation(enrollmentRequest)
if (!attestResp.verdict.isVerified) {
    return forbid(attestResp.verdict)
}

// Step 2: Verify immediate biometric Proof-of-Possession -> activates binding & revokes prior
// devices beyond policy.maxActiveBindingsPerAccount
val confirmResp = verifier.confirmEnrollmentPop(confirmRequest)
check(confirmResp.status == EnrollmentStatus.ACTIVE)

// Device management (lost/stolen phone or "remove this device"):
verifier.revokeBinding(bindingId)
// or revoke all devices on account takeover:
verifier.revokeAccountBindings(user.id)
// Periodic cleanup for abandoned PENDING_POP enrollments:
verifier.purgeExpiredPendingEnrollments()

// Transaction Step A: Issue single-use nonce bound to active keyId
val txChallenge = verifier.issueTransactionNonce(accountId = user.id, keyId = keyId, ttlSeconds = 90)

// Transaction Step B: Verify signature + nonce + field-by-field parity with server business command
val verdict = verifier.verifyTransaction(
    accountId = user.id,
    signedPayload = request.signedPayload,
    expectedOperationType = "PIX_TRANSFER",
    expectedFields = canonicalFields(
        "amountCents" to canonical(command.amountCents), // extracted from server command
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
// Instantiate once as an Application-scoped singleton (e.g., Hilt @Singleton / Koin single)
val maigBind = MaigBind(
    context = applicationContext,
    config = MaigBindConfig(
        preferStrongBox = true,                     // try StrongBox, fall back to TEE
        requireStrongBox = false,                   // set true to reject TEE-only devices
        includeDevicePropertiesAttestation = false, // optional Device ID attestation (API 31+)
    ),
)

// Check Class 3 (BIOMETRIC_STRONG) readiness
when (maigBind.getBiometricCapability()) {
    BiometricCapability.READY_STRONG -> { /* ready */ }
    BiometricCapability.NONE_ENROLLED -> { /* prompt user to enroll fingerprint/face in Settings */ }
    else -> { /* show unsupported / fallback UX */ }
}

// Enrollment Step 1: Generate hardware key (always stages as pending — even first-time enrollment)
val enrollReq = when (val res = maigBind.enroll(accountId, beginResp.challengeBase64Url)) {
    is MaigBindResult.Success -> res.value
    is MaigBindResult.Failure -> return handleMaigBindError(res.error)
}
val attestResp = api.postEnrollAttest(enrollReq)
if (!attestResp.verdict.isVerified) {
    maigBind.abortPendingEnrollment(accountId)
    return
}

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
    is MaigBindResult.Failure -> {
        maigBind.abortPendingEnrollment(accountId)
        return handleMaigBindError(res.error)
    }
}
val confirmResp = api.postEnrollConfirm(popReq)
if (confirmResp.status == EnrollmentStatus.ACTIVE) {
    maigBind.activatePendingEnrollment(accountId) // atomically promotes pending key & deletes superseded key
} else {
    maigBind.abortPendingEnrollment(accountId)
}

// Crash recovery on app launch: query server's active keyIds (e.g. GET /bindings/active).
// IMPORTANT: only call reconcileActiveKey when the server query succeeded (never on network errors).
val activeResp = api.getActiveBindings(accountId).getOrNull()
if (activeResp != null) {
    when (val sync = maigBind.reconcileActiveKey(accountId, activeResp.activeKeyIds.toSet())) {
        is MaigBindResult.Success -> when (sync.value) {
            ReconciliationOutcome.PROMOTED_PENDING -> { /* crash happened right after server ACTIVE; recovered */ }
            ReconciliationOutcome.NEEDS_RE_ENROLLMENT -> startStepUpEnrollment()
            ReconciliationOutcome.UP_TO_DATE,
            ReconciliationOutcome.NOT_ENROLLED -> { /* expected steady state; staged pending keys are preserved */ }
        }
        is MaigBindResult.Failure -> handleMaigBindError(sync.error)
    }
}

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
suspend fun handleMaigBindError(error: MaigBindError) {
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
        is MaigBindError.LocalStateCorrupted -> {
            maigBind.resetAll()
            startStepUpEnrollment()
        }
        is MaigBindError.InvalidInput,
        is MaigBindError.PlatformFailure -> showGenericError(error.message)
    }
}
```

#### Exclude `maigbind_slots.xml` from Android Auto Backup

MaigBind derives alias identifiers via a non-exportable `AndroidKeyStore` HMAC-SHA256 key (`maigbind:alias_hmac_v1`, never leaving hardware/Keystore) and stores active/pending alias pointers in `SharedPreferences` (`maigbind_slots.xml`). If Auto Backup restores `maigbind_slots.xml` onto a new phone or clean reinstall, those alias pointers will reference non-existent hardware keys (falling back to `NotEnrolled`). Exclude it in your manifest's backup rules:

```xml
<!-- res/xml/data_extraction_rules.xml (Android 12+) -->
<data-extraction-rules>
    <cloud-backup>
        <exclude domain="sharedpref" path="maigbind_slots.xml" />
    </cloud-backup>
    <device-transfer>
        <exclude domain="sharedpref" path="maigbind_slots.xml" />
    </device-transfer>
</data-extraction-rules>

<!-- res/xml/backup_rules.xml (Android 11 and below) -->
<full-backup-content>
    <exclude domain="sharedpref" path="maigbind_slots.xml" />
</full-backup-content>
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

## Threat Model Summary & External References

See [THREAT_MODEL.md](THREAT_MODEL.md) and [PROTOCOL.md](PROTOCOL.md) for the complete analysis and Mermaid sequence diagrams.

- **Frida callback hooking (T1):** The authoritative defense is **server-side ECDSA verification** against the hardware-attested public key — KeyMint/StrongBox will not sign without a valid hardware biometric `AuthToken` from `BIOMETRIC_STRONG` + `CryptoObject`. The client's `result.cryptoObject?.signature === signature` reference check provides **defense-in-depth** to fail fast on simple hooks (acknowledging Frida can also hook client-side comparisons).
- **Google RKP Root Rotation (2026):** `maigbind-verifier` fetches both the legacy RSA root and the ECDSA P-384 root (*Key Attestation CA1*) from `https://android.googleapis.com/attestation/root` (rolled out Feb 2026; exclusive RKP cutover **April 10, 2026**) and checks revocations at `https://android.googleapis.com/attestation/status`.
- **Quarkslab Attestation Relay (Aug 11, 2026):** Based on Eric Le Guevel's *"Bypassing Android Hardware Attestation from the Analyst's Chair"* (Aug 11, 2026), one-shot relay is blocked by `attestationApplicationId` (Tag 709) + immediate biometric Proof-of-Possession before binding activation + per-transaction PoP.

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
