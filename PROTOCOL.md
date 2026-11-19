# MaigBind Protocol Specification (v1)

> **Project:** MaigBind (`io.github.maignardi`) — Apache 2.0  
> **Protocol Version:** `1`  
> **Modules:** `maigbind-core` (KMP), `maigbind-android`, `maigbind-verifier` (JVM), `maigbind-ios` (Phase 2)

---

## 1. Design Principles

1. **Zero Client Trust:** The client produces cryptographic evidence (`EnrollmentAttestation`, `SignedPayload`); the server (`maigbind-verifier`) makes all policy and authorization decisions.
2. **Deterministic Canonical Bytes:** Both client and server must independently reconstruct the exact same byte sequence for signing and verification without relying on fragile string formatting.
3. **Domain Separation:** Signatures generated for one protocol context (e.g., enrollment proof-of-possession) can never be reinterpreted in another context (e.g., transaction authorization).
4. **Two-Phase Enrollment:** Hardware key attestation proves *what kind of hardware and app* created a key; immediate biometric Proof-of-Possession (PoP) proves *live control* of that private key before activation.

---

## 2. Cryptographic Primitives & Wire Formats

| Element | Specification | Notes |
|---|---|---|
| **Asymmetric Key** | ECDSA on NIST P-256 (`secp256r1` / `prime256v1`) | Non-exportable, generated in StrongBox / TEE (Android) or Secure Enclave (iOS). |
| **Hash & Signature** | `SHA256withECDSA` | Standard ASN.1 DER-encoded `(r, s)` signature output. |
| **Public Key Format** | X.509 `SubjectPublicKeyInfo` (SPKI) DER | Unpadded `base64url` (RFC 4648 §5) for JSON/HTTP transport. |
| **Signature Format** | ASN.1 DER `(r, s)` | Unpadded `base64url` (RFC 4648 §5). |
| **Key Identifier (`keyId`)** | `base64url(SHA-256(spkiDerBytes))` | 43-char deterministic JWK-thumbprint-style identifier. |
| **Certificate Chain** | Array of X.509 DER certificates | Unpadded `base64url`, ordered leaf-first: `[leaf, intermediate..., rootOrPenultimate]`. |
| **Canonical Serialization** | **Deterministic CBOR (RFC 8949 §4.2)** | See Section 3 for rationale and exact encoding rules. |

---

## 3. Canonical Serialization: Why Deterministic CBOR (RFC 8949 §4.2)?

MaigBind uses **Deterministic CBOR (RFC 8949 §4.2)** rather than JSON Canonicalization Scheme (JCS / RFC 8785) for the following reasons:

1. **Unambiguous Numeric & Binary Types:** JSON has no native integer vs. floating-point distinction (`100` vs `100.0` vs `1e2`) and loses precision on 64-bit timestamps/minor-unit amounts unless stringified. CBOR encodes 64-bit signed integers, booleans, UTF-8 strings, and raw byte strings unambiguously.
2. **Compact & Allocation-Light:** Binary CBOR has no whitespace, delimiter, or Unicode-escape ambiguity and maps cleanly to a small, zero-reflection KMP `commonMain` encoder/decoder.
3. **Ecosystem Alignment:** FIDO2/WebAuthn and Apple App Attest both standardize on Deterministic CBOR.

### Deterministic Encoding Rules (RFC 8949 §4.2)

- **Minimal Integer Length:** Integers (major types `0` and `1`) must use the shortest possible encoding (0–23 inline, then 1, 2, 4, or 8 bytes).
- **Definite Lengths Only:** Indefinite-length items (`0x5F`, `0x7F`, `0x9F`, `0xBF`) are forbidden.
- **Map Key Ordering:** Map keys are sorted in **bytewise lexicographical order of their encoded CBOR bytes** (i.e., shortest encoded key first, then unsigned byte comparison — RFC 8949 §4.2.1).
- **No Floating-Point Values in `CanonicalValue`:** Monetary amounts and quantities must be represented as 64-bit integers (minor units, e.g., `amountCents = 150000`) or canonical decimal strings to eliminate IEEE-754 representation hazards.
- **Duplicate Keys Forbidden:** Encoders never emit duplicate keys; decoders reject duplicate keys as malformed.

---

## 4. Domain Separation

Every signature is computed over:

```text
signingInput = ASCII(domainTag) || 0x00 || deterministicCbor(payload)
```

| Context | `domainTag` | Purpose |
|---|---|---|
| **Enrollment Proof-of-Possession** | `"MaigBind/v1/enroll-pop"` | Proves live biometric-unlocked possession of the newly attested key during enrollment. |
| **Transaction / Operation** | `"MaigBind/v1/tx"` | Authorizes a specific sensitive operation (`TransactionPayload`). |

The `0x00` separator guarantees prefix-freedom between domain tags and CBOR payload headers.

---

## 5. Canonical Data Models (`maigbind-core`)

### 5.1 `CanonicalValue` (Closed Algebraic Type)

To prevent ambiguous serialization across platforms, custom transaction `fields` only accept:
- `Text(value: String)` (CBOR major type 3)
- `Int64(value: Long)` (CBOR major type 0 or 1)
- `Bool(value: Boolean)` (CBOR major type 7: `0xF4` / `0xF5`)
- `Bytes(value: ByteArray)` (CBOR major type 2)
- `ListValue(items: List<CanonicalValue>)` (CBOR major type 4)
- `MapValue(entries: Map<String, CanonicalValue>)` (CBOR major type 5, sorted keys)

### 5.2 `EnrollmentPoPPayload`

Serialized as a CBOR map with deterministic key order:

```cddl
EnrollmentPoPPayload = {
  "accountId": tstr,
  "challenge": tstr,       ; base64url server popChallenge
  "expiresAt": int,        ; Unix epoch milliseconds
  "issuedAt": int,         ; Unix epoch milliseconds
  "keyId": tstr,           ; base64url(SHA-256(spkiDer))
  "protocolVersion": 1
}
```

### 5.3 `TransactionPayload`

Serialized as a CBOR map with deterministic key order:

```cddl
TransactionPayload = {
  "expiresAt": int,                 ; Unix epoch milliseconds
  "fields": { * tstr => any },      ; Integrator-defined operation fields (CanonicalValue)
  "issuedAt": int,                  ; Unix epoch milliseconds
  "keyId": tstr,                    ; base64url(SHA-256(spkiDer))
  "nonce": tstr,                    ; base64url CSPRNG single-use server nonce
  "operationType": tstr,            ; e.g., "PIX_TRANSFER", "CHANGE_LIMIT"
  "protocolVersion": 1
}
```

### 5.4 Transport Envelopes

- **`SignedPayload`** (client -> server):
  - `payload: TransactionPayload`
  - `signatureBase64Url: String` (DER ECDSA `(r, s)`)
  *(Note: `securityBacking` and biometric enforcement properties are retrieved on the server from the attested `DeviceBinding` persisted during enrollment, never trusted from unsigned client metadata.)*
- **`VerificationVerdict`** (server result):
  - `status: VerdictStatus` (`VERIFIED`, `REJECTED_POLICY`, `REJECTED_FRAUD_SIGNAL`, `ERROR_VALIDATION_INFRA`)
  - `keyId: String?`
  - `findings: List<Finding>` (each with stable `code: FindingCode`, `severity: FindingSeverity`, `message: String`, `details: Map<String, String>`)

---

## 6. Protocol Flows

### 6.1 Enrollment Sequence Diagram (Attestation + Immediate Proof-of-Possession)

```mermaid
sequenceDiagram
    autonumber
    participant U as User (Biometrics)
    participant C as App + maigbind-android
    participant HW as StrongBox / TEE
    participant S as Backend + maigbind-verifier

    Note over C,S: Precondition: User authenticated + Step-Up Auth (MFA/eKYC) completed
    C->>S: POST /enroll/begin (accountId)
    S->>S: Generate attestationChallenge (CSPRNG, 32B, TTL 120s)
    S-->>C: 200 OK { attestationChallenge, expiresAt }

    C->>HW: KeyPairGenerator.generateKeyPair()<br/>P-256, PURPOSE_SIGN, timeout=0, AUTH_BIOMETRIC_STRONG,<br/>invalidatedByBiometricEnrollment=true, unlockedDeviceRequired=true,<br/>attestationChallenge=C1
    HW-->>C: Non-exportable privateKey + X.509 attestationChain
    C->>C: Compute keyId = base64url(SHA-256(spki))

    C->>S: POST /enroll/attest { accountId, keyId, publicKeySpki, attestationChain, securityBacking }
    S->>S: Consume C1 (single-use, check TTL)
    S->>S: Fetch/Cache Google Roots (RSA + ECDSA P-384)<br/>& Revocation Status (/attestation/status)
    S->>S: Validate PKIX chain, validity dates, non-revocation
    S->>S: Parse OID 1.3.6.1.4.1.11129.2.1.17:<br/>hardwareEnforced (VERIFIED boot, deviceLocked, AUTH_BIOMETRIC, timeout=0, patchLevel)<br/>softwareEnforced.attestationApplicationId (pkg + SHA-256 cert)<br/>leaf public key == publicKeySpki + keybox heuristics
    S->>S: Persist DeviceBinding (status = PENDING_POP)<br/>Generate popChallenge C2 (32B, TTL 60s)
    S-->>C: 200 OK { bindingId, keyId, popChallenge, expiresAt }

    C->>C: Build EnrollmentPoPPayload(C2) +<br/>signingInput = "MaigBind/v1/enroll-pop\0" || CBOR(payload)
    C->>HW: Signature.initSign(privateKey)
    C->>U: BiometricPrompt.authenticate(promptInfo, CryptoObject(signature))
    U->>HW: Strong Biometric authentication
    HW-->>C: AuthToken + onAuthenticationSucceeded(result)
    C->>C: Verify result.cryptoObject.signature === signature<br/>signature.update(signingInput); sig = signature.sign()

    C->>S: POST /enroll/confirm { bindingId, popPayload, signatureBase64Url }
    S->>S: Consume C2, verify domain tag + ECDSA(publicKeySpki, signingInput, sig)
    S->>S: Transition DeviceBinding -> ACTIVE
    S-->>C: 200 OK { bindingId, keyId, status: ACTIVE }
```

---

### 6.2 Transaction Signing & Verification Sequence Diagram

```mermaid
sequenceDiagram
    autonumber
    participant U as User (Biometrics)
    participant C as App + maigbind-android
    participant HW as StrongBox / TEE
    participant S as Backend + maigbind-verifier

    U->>C: Initiate sensitive op (e.g., Transfer $150.00 to Bob)
    C->>S: POST /tx/challenge { accountId, keyId, operationType }
    S->>S: Verify ACTIVE DeviceBinding exists<br/>Generate CSPRNG nonce (32B, TTL 90s)
    S-->>C: 200 OK { nonce, issuedAt, expiresAt }

    C->>C: Build TransactionPayload { protocolVersion=1, keyId, operationType,<br/>nonce, issuedAt, expiresAt, fields: { amountCents: 15000, currency: "USD", to: "bob" } }
    C->>C: signingInput = "MaigBind/v1/tx\0" || deterministicCbor(payload)

    C->>HW: Signature.initSign(privateKey)
    C->>U: BiometricPrompt.authenticate(PromptInfo("Transfer $150.00 to Bob"), CryptoObject(signature))
    U->>HW: Strong Biometric authentication
    HW-->>C: AuthToken + onAuthenticationSucceeded(result)
    C->>C: Verify result.cryptoObject != null &&<br/>result.cryptoObject.signature === signature<br/>signature.update(signingInput); sig = signature.sign()

    C->>S: POST /tx/execute { signedPayload, expectedCommand }
    S->>S: Lookup ACTIVE binding for (accountId, keyId)
    S->>S: Atomic NonceStore.consumeIfUnused(nonce) + verify timestamps
    S->>S: Reconstruct canonical signingInput = "MaigBind/v1/tx\0" || deterministicCbor(payload)
    S->>S: Verify ECDSA-P256(enrolledPublicKey, signingInput, sig)
    S->>S: Field-by-field equality check: verified payload.fields == expectedCommand
    S->>S: Evaluate VerificationPolicy -> VerificationVerdict (VERIFIED / REJECTED)
    S->>S: Execute business transaction only if VERIFIED
    S-->>C: 200 OK { verdict, transactionId }
```

---

## 7. Server-Side Attestation Verification Rules (`maigbind-verifier`)

### 7.1 Evaluation of `github.com/android/keyattestation`

We evaluated `github.com/android/keyattestation` (Google's official Kotlin replacement for the archived `google/android-key-attestation` library). While its ASN.1 modeling is the canonical reference, **it is not published on Maven Central or GMaven** (requiring source vendoring or Bazel builds). Because MaigBind is itself distributed as a Maven Central library (`io.github.maignardi:maigbind-verifier`), depending on an unpublished library would break downstream Gradle/Maven builds.

**Decision:** `maigbind-verifier` implements a dedicated, self-contained X.509 + ASN.1 `KeyDescription` verifier backed by Bouncy Castle (`org.bouncycastle:bcpkix-jdk18on` / `bcprov-jdk18on`) and standard `java.security.cert`, strictly adhering to the AOSP Key Attestation ASN.1 schema (`OID 1.3.6.1.4.1.11129.2.1.17`) and validated against Google's official sample attestation chains.

### 7.2 Trust Anchors & Root Rotation (April 2026 RKP Migration)

- **Dual-Root Trust:** `maigbind-verifier` trusts **both**:
  1. Legacy Google RSA hardware attestation root(s) (devices with factory-provisioned keys).
  2. Google ECDSA P-384 root certificate used by Remote Key Provisioning (RKP), to which RKP-enabled devices transitioned exclusively on **April 10, 2026**.
- **Dynamic Refresh + Embedded Fallback:** Roots are fetched from `https://android.googleapis.com/attestation/root` with HTTP caching (configurable TTL, ETag/Last-Modified support) and bundled embedded fallback roots for offline/air-gapped tests or transient outages.
- **PKIX Validation:** Full `PKIXParameters` / `CertPathValidator` validation over arbitrary chain lengths (supporting shorter RKP chains and longer factory chains), enforcing `notBefore` / `notAfter` validity (critical for short-lived RKP certificates).

### 7.3 Revocation Checking

- Status map fetched from `https://android.googleapis.com/attestation/status` (`entries.<lowercase_hex_serial>.status`).
- Any certificate in the chain whose serial is marked `REVOKED` or `SUSPENDED` causes immediate rejection (`ATTESTATION_CERT_REVOKED`).
- Infrastructure failures (network timeout, stale cache beyond max grace period) emit `ERROR_VALIDATION_INFRA` and follow explicit, logged `VerificationPolicy.failMode` (`FAIL_CLOSED` by default).

### 7.4 Attestation Extension (`OID 1.3.6.1.4.1.11129.2.1.17`) Checklist

| Field | Location | Policy Requirement |
|---|---|---|
| `attestationChallenge` | Top-level `KeyDescription` | Exact byte-for-byte match with single-use server challenge. |
| `attestationSecurityLevel` | Top-level `KeyDescription` | `TRUSTED_ENVIRONMENT` or `STRONG_BOX` (never `SOFTWARE`). |
| `keymasterSecurityLevel` | Top-level `KeyDescription` | `TRUSTED_ENVIRONMENT` or `STRONG_BOX` (never `SOFTWARE`). |
| `rootOfTrust` | `hardwareEnforced` | `verifiedBootState == VERIFIED` AND `deviceLocked == true`. |
| `purpose` | `hardwareEnforced` | Contains `KM_PURPOSE_SIGN` (`2`); reject `ENCRYPT`/`DECRYPT` if strict. |
| `algorithm` & `ecCurve` | `hardwareEnforced` | `EC` (`3`) and `P_256` (`1`). |
| `noAuthRequired` | `hardwareEnforced` | **Must be absent.** |
| `userAuthType` | `hardwareEnforced` | Must include biometric (`HARDWARE_AUTH_TYPE_FINGERPRINT` / biometric bit `2`); reject password-only by default. |
| `authTimeout` | `hardwareEnforced` | Absent or `0` (per-use authentication). |
| `osPatchLevel` | `hardwareEnforced` | `>= policy.minOsPatchLevel` (YYYYMM) when configured. |
| `attestationApplicationId` | `softwareEnforced` (Tag `709`) | Package name + SHA-256 signing cert digest(s) must match `policy.expectedApps`. Trusted **only** when `hardwareEnforced.rootOfTrust` is verified. |
| Leaf SPKI | X.509 Leaf Certificate | Must match `publicKeySpki` submitted by the client. |

---

## 8. Android Client Requirements (`maigbind-android`)

- **minSdk:** `24` (Android 7.0 — first API level supporting hardware Key Attestation).
- **Alias Isolation, Keystore-HMAC Non-PII & Crash-Safe Staging:** Keystore aliases use `maigbind:<hmac_sha256(keystoreHmacKey, accountId) prefix>:<randomTag>`, where `keystoreHmacKey` (`maigbind:alias_hmac_v1`) is a non-exportable `KeyProperties.KEY_ALGORITHM_HMAC_SHA256` key in `AndroidKeyStore` (requiring no biometric unlock). Because the HMAC key never enters `SharedPreferences`, reading `maigbind_slots.xml` alone does not enable offline brute-force reversal of low-entropy identifiers such as tax IDs/CPFs, and Keystore itself never sees raw PII. Every `enroll()` call (both initial and re-enrollment) stages the new key under a `pending` slot and leaves the `active` slot untouched until `activatePendingEnrollment(accountId)` atomically checks `SharedPreferences.commit()` and deletes any superseded key. If the app crashes right after the server activates a binding, `reconcileActiveKey(accountId, serverActiveKeyIds)` promotes the matching staged key on next startup, and preserves staged `pending` enrollments when `serverActiveKeyIds` is empty.
- **Key Generation (`KeyGenParameterSpec`):**
  - `KEY_ALGORITHM_EC`, `PURPOSE_SIGN`, `DIGEST_SHA256`, `ECGenParameterSpec("secp256r1")`.
  - `setUserAuthenticationRequired(true)`.
  - API 30+: `setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)`.
  - API < 30: `setUserAuthenticationValidityDurationSeconds(-1)`.
  - API 24+: `setInvalidatedByBiometricEnrollment(true)`.
  - API 28+: `setUnlockedDeviceRequired(true)` (with defensive handling for Android 12–14 lock-screen-removal key deletion behavior).
  - API 28+: `setIsStrongBoxBacked(true)` with explicit fallback to TEE on `StrongBoxUnavailableException`, reporting `SecurityBacking.STRONGBOX` vs `SecurityBacking.TEE`.
  - `setAttestationChallenge(serverChallenge)`.
  - Optional/configurable Device ID attestation (`setDevicePropertiesAttestationIncluded` / ID attestation flags when explicitly permitted by caller & platform).
- **Prompt & Signing Flow:**
  - `BiometricManager.Authenticators.BIOMETRIC_STRONG` only by default.
  - Pre-initialize `Signature.getInstance("SHA256withECDSA").initSign(privateKey)`.
  - Call `BiometricPrompt.authenticate(promptInfo, CryptoObject(signature))` displaying transaction summary in `PromptInfo`.
  - Inside `onAuthenticationSucceeded`: enforce `result.cryptoObject?.signature === signature` before `update(signingInput)` and `sign()`.
  - All Keystore / Biometric errors map to sealed `MaigBindError` (`NeedsReEnrollment`, `NotEnrolled`, `BiometryUnavailable`, `BiometryNotEnrolled`, `Lockout`, `Cancelled`, `UserNotAuthenticated`, `CryptoObjectTampered`, `HardwareUnavailable`, `LocalStateCorrupted`, `InvalidInput`, `PlatformFailure`).

---

## 9. Phase 2: iOS Architecture (`maigbind-ios` — Interface Design)

Phase 2 shares the exact `maigbind-core` `TransactionPayload`, Deterministic CBOR encoding, `"MaigBind/v1/tx\0"` domain separation, SPKI public key format, and DER ECDSA signature format:

1. **Biometric Signing Key (Secure Enclave):**
   - P-256 key created with `SecKeyCreateRandomKey` (`kSecAttrTokenIDSecureEnclave`, `kSecAttrKeyTypeECSECPrimeRandom`, 256-bit).
   - Protected via `SecAccessControlCreateWithFlags(..., kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly, [.privateKeyUsage, .biometryCurrentSet], ...)`.
   - Signed with `LAContext` (`localizedReason` showing transaction summary) and `SecKeyCreateSignature(..., .ecdsaSignatureMessageX962SHA256, ...)`.
2. **App & Device Attestation (`DCAppAttestService`):**
   - Because standalone Secure Enclave keys do not emit X.509 attestation chains like Android Keystore, enrollment uses `DCAppAttestService.generateKey` + `attestKey(_:clientDataHash:)` over `SHA256(serverChallenge || spkiDer)` (or `generateAssertion` binding the Secure Enclave signing public key to the App Attest key).
   - `maigbind-verifier` validates the Apple CBOR attestation object (Apple App Attest Root CA, `authData.rpIdHash == SHA256(teamId + "." + bundleId)`, receipt/aaguid environment) and binds the attested Secure Enclave key.
