package io.github.maignardi.maigbind.ios

import io.github.maignardi.maigbind.core.EnrollmentConfirmRequest
import io.github.maignardi.maigbind.core.EnrollmentRequest
import io.github.maignardi.maigbind.core.MaigBindResult
import io.github.maignardi.maigbind.core.PromptText
import io.github.maignardi.maigbind.core.SignedPayload
import io.github.maignardi.maigbind.core.TransactionPayload

/**
 * Phase 2 iOS enrollment request extending the shared protocol with Apple App Attest
 * (`DCAppAttestService`) artifacts.
 *
 * Official Apple references:
 * - DCAppAttestService: https://developer.apple.com/documentation/devicecheck/dcappattestservice
 * - Secure Enclave keys & SecAccessControl:
 *   https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_secure_enclave
 * - LAContext biometric prompting:
 *   https://developer.apple.com/documentation/localauthentication/lacontext
 *
 * Design notes:
 * - Biometric signing key: P-256 (`kSecAttrKeyTypeECSECPrimeRandom`, 256-bit) stored in Secure
 *   Enclave (`kSecAttrTokenIDSecureEnclave`) with `SecAccessControlCreateWithFlags` using
 *   `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and `[.privateKeyUsage, .biometryCurrentSet]`
 *   so enrolling a new Face ID / Touch ID invalidates the key.
 * - Attestation binding: `DCAppAttestService.generateKey` + `attestKey(_:clientDataHash:)` where
 *   `clientDataHash = SHA256(serverChallenge || signingKeySpkiDer)`, linking the Apple-attested
 *   App Attest key to the Secure Enclave biometric signing public key.
 */
public data class IosEnrollmentBundle(
    val coreEnrollment: EnrollmentRequest,
    val appAttestKeyId: String,
    val appAttestObjectBase64Url: String,
)

/**
 * Phase 2 interface for the iOS MaigBind client SDK.
 *
 * Shares the exact same [TransactionPayload], Deterministic CBOR serialization, `"MaigBind/v1/tx\u0000"`
 * domain tag, X.509 SPKI public key format, and ASN.1 DER ECDSA `(r, s)` signature format as
 * `maigbind-android` and `maigbind-verifier`.
 */
public interface MaigBindIos {
    /**
     * Generates a P-256 key in Secure Enclave protected with `[.privateKeyUsage, .biometryCurrentSet]`
     * and attests the app + device via `DCAppAttestService.attestKey`.
     */
    public suspend fun enroll(
        accountId: String,
        serverChallengeBase64Url: String,
    ): MaigBindResult<IosEnrollmentBundle>

    /**
     * Performs Step-2 Proof-of-Possession using `LAContext` + `SecKeyCreateSignature`
     * (`.ecdsaSignatureMessageX962SHA256`) over `"MaigBind/v1/enroll-pop\u0000" || CBOR(popPayload)`.
     */
    public suspend fun confirmEnrollmentPop(
        accountId: String,
        bindingId: String,
        popChallengeBase64Url: String,
        issuedAt: Long,
        expiresAt: Long,
        promptText: PromptText,
    ): MaigBindResult<EnrollmentConfirmRequest>

    /**
     * Prompts the user via `LAContext` and signs [payload] using the Secure Enclave key.
     */
    public suspend fun sign(
        accountId: String,
        payload: TransactionPayload,
        promptText: PromptText,
    ): MaigBindResult<SignedPayload>

    /**
     * Deletes the Secure Enclave key item for [accountId] from the Keychain.
     */
    public suspend fun unenroll(accountId: String): MaigBindResult<Unit>
}
