package io.github.maignardi.maigbind.core

/**
 * Typed client-side error states returned or thrown by MaigBind SDKs instead of crashing.
 */
public sealed class MaigBindError {
    public abstract val message: String

    /**
     * Keystore key was permanently invalidated (for example, after a new fingerprint/face was
     * enrolled on the device or lock screen credentials were removed).
     * The user must perform an authenticated step-up re-enrollment.
     */
    public data class NeedsReEnrollment(
        override val message: String = "Hardware key permanently invalidated; re-enrollment required",
    ) : MaigBindError()

    /** No hardware key is enrolled for the requested `accountId`. */
    public data class NotEnrolled(
        val accountId: String,
        override val message: String = "No enrolled hardware key found for account '$accountId'",
    ) : MaigBindError()

    /** Strong biometric hardware is unavailable, unsupported, or disabled on this device. */
    public data class BiometryUnavailable(
        val reasonCode: Int? = null,
        override val message: String = "Strong biometric authentication is unavailable on this device",
    ) : MaigBindError()

    /** Device supports biometrics, but the user has not enrolled any biometric credentials. */
    public data class BiometryNotEnrolled(
        override val message: String = "No biometric credentials are enrolled on this device",
    ) : MaigBindError()

    /** Biometric authentication is temporarily or permanently locked out due to failed attempts. */
    public data class Lockout(
        val isPermanent: Boolean,
        override val message: String,
    ) : MaigBindError()

    /** User cancelled the biometric prompt or tapped the negative button. */
    public data class Cancelled(
        val errorCode: Int? = null,
        override val message: String = "Biometric prompt cancelled by user",
    ) : MaigBindError()

    /** Keystore rejected signing because a valid per-use biometric AuthToken was not present. */
    public data class UserNotAuthenticated(
        override val message: String = "User authentication is required to unlock the hardware key",
    ) : MaigBindError()

    /**
     * Fatal integrity failure: `BiometricPrompt.AuthenticationResult.cryptoObject` was null or
     * did not match the exact `Signature` instance created before prompting (possible Frida hook).
     */
    public data class CryptoObjectTampered(
        override val message: String = "BiometricPrompt CryptoObject missing or tampered",
    ) : MaigBindError()

    /** Required secure hardware (e.g., StrongBox when strict StrongBox is requested) is unavailable. */
    public data class HardwareUnavailable(
        override val message: String,
    ) : MaigBindError()

    /** Caller passed invalid arguments (e.g., blank accountId or empty challenge). */
    public data class InvalidInput(
        override val message: String,
    ) : MaigBindError()

    /**
     * Local alias derivation key or slot state is corrupted (e.g., the `AndroidKeyStore` HMAC
     * key became unreadable). Call `resetAll()` to wipe local state and re-enroll via step-up.
     */
    public data class LocalStateCorrupted(
        override val message: String =
            "Local MaigBind key state is corrupted; call resetAll() and re-enroll",
    ) : MaigBindError()

    /** Unexpected platform Keystore/Cryptographic failure. */
    public data class PlatformFailure(
        override val message: String,
        val causeName: String? = null,
    ) : MaigBindError()
}

/**
 * Exception wrapper carrying a typed [MaigBindError].
 */
public class MaigBindException(
    public val error: MaigBindError,
    cause: Throwable? = null,
) : Exception(error.message, cause)

/**
 * Result container returned by client SDK operations so callers can handle every failure branch
 * exhaustively without catching runtime exceptions.
 */
public sealed class MaigBindResult<out T> {
    public data class Success<T>(
        val value: T,
    ) : MaigBindResult<T>()

    public data class Failure(
        val error: MaigBindError,
    ) : MaigBindResult<Nothing>()
}
