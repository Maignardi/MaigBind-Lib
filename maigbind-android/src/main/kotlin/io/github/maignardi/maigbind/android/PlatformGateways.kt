package io.github.maignardi.maigbind.android

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.github.maignardi.maigbind.core.Base64Url
import io.github.maignardi.maigbind.core.SecurityBacking
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import kotlin.coroutines.resume

/**
 * Production Android Keystore gateway implementing hardware-backed P-256 key generation and
 * attestation certificate chain extraction.
 *
 * API references:
 * - `KeyGenParameterSpec.Builder.setUserAuthenticationParameters` (API 30+):
 *   https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUserAuthenticationParameters(int,%20int)
 * - `KeyGenParameterSpec.Builder.setUnlockedDeviceRequired` (API 28+, noting API 31–34 lock-screen
 *   removal caveats):
 *   https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setUnlockedDeviceRequired(boolean)
 * - `KeyGenParameterSpec.Builder.setIsStrongBoxBacked` (API 28+):
 *   https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setIsStrongBoxBacked(boolean)
 * - `KeyGenParameterSpec.Builder.setDevicePropertiesAttestationIncluded` (API 31+):
 *   https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder#setDevicePropertiesAttestationIncluded(boolean)
 */
internal class PlatformAndroidKeyStoreGateway : AndroidKeyStoreGateway {
    override fun generateHardwareKey(
        alias: String,
        attestationChallenge: ByteArray,
        config: MaigBindConfig,
    ): GeneratedKeyMaterial {
        val tryStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && config.preferStrongBox
        var usedStrongBox = false

        if (tryStrongBox) {
            try {
                generateWithDeviceIdFallback(
                    alias = alias,
                    attestationChallenge = attestationChallenge,
                    useStrongBox = true,
                    includeDeviceIdAttestation = config.includeDevicePropertiesAttestation,
                )
                usedStrongBox = true
            } catch (ex: StrongBoxUnavailableException) {
                if (config.requireStrongBox) throw ex
            } catch (ex: ProviderException) {
                if (config.requireStrongBox || !isStrongBoxUnavailableCause(ex)) throw ex
            }
        }

        if (!usedStrongBox) {
            if (config.requireStrongBox) {
                throw StrongBoxUnavailableException("StrongBox requires Android 9 (API 28) or higher")
            }
            generateWithDeviceIdFallback(
                alias = alias,
                attestationChallenge = attestationChallenge,
                useStrongBox = false,
                includeDeviceIdAttestation = config.includeDevicePropertiesAttestation,
            )
        }

        val ks = loadKeyStore()
        val chain =
            ks.getCertificateChain(alias)
                ?: throw IllegalStateException("AndroidKeyStore returned null certificate chain for $alias")
        val spki = chain.first().publicKey.encoded
        val backing = if (usedStrongBox) SecurityBacking.STRONGBOX else SecurityBacking.TEE
        return GeneratedKeyMaterial(
            publicKeySpkiDer = spki,
            attestationChainDer = chain.map { it.encoded },
            securityBacking = backing,
        )
    }

    private fun generateWithDeviceIdFallback(
        alias: String,
        attestationChallenge: ByteArray,
        useStrongBox: Boolean,
        includeDeviceIdAttestation: Boolean,
    ) {
        try {
            generateWithSpec(
                alias = alias,
                attestationChallenge = attestationChallenge,
                useStrongBox = useStrongBox,
                includeDeviceIdAttestation = includeDeviceIdAttestation,
            )
        } catch (ex: ProviderException) {
            // Re-throw StrongBox unavailability so outer caller can fall back to TEE;
            // otherwise retry without device properties attestation if that flag triggered the failure.
            if (isStrongBoxUnavailableCause(ex) || !includeDeviceIdAttestation) {
                throw ex
            }
            generateWithSpec(
                alias = alias,
                attestationChallenge = attestationChallenge,
                useStrongBox = useStrongBox,
                includeDeviceIdAttestation = false,
            )
        }
    }

    private fun generateWithSpec(
        alias: String,
        attestationChallenge: ByteArray,
        useStrongBox: Boolean,
        includeDeviceIdAttestation: Boolean,
    ) {
        val builder =
            KeyGenParameterSpec
                .Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
                .setAttestationChallenge(attestationChallenge)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Timeout 0 requires strong biometric authentication for every individual signature.
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setUnlockedDeviceRequired(true)
            builder.setIsStrongBoxBacked(useStrongBox)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && includeDeviceIdAttestation) {
            builder.setDevicePropertiesAttestationIncluded(true)
        }

        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        kpg.initialize(builder.build())
        kpg.generateKeyPair()
    }

    override fun getPrivateKeyOrNull(alias: String): PrivateKey? {
        val ks = loadKeyStore()
        if (!ks.containsAlias(alias)) return null
        return ks.getKey(alias, null) as? PrivateKey
    }

    override fun getPublicKeySpkiOrNull(alias: String): ByteArray? {
        val ks = loadKeyStore()
        return ks.getCertificate(alias)?.publicKey?.encoded
    }

    override fun getKeySecurityBacking(
        alias: String,
        privateKey: PrivateKey,
    ): SecurityBacking =
        runCatching {
            val factory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
            val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                mapSecurityLevelApi31(keyInfo)
            } else {
                @Suppress("DEPRECATION")
                if (keyInfo.isInsideSecureHardware) SecurityBacking.TEE else SecurityBacking.UNKNOWN
            }
        }.getOrDefault(SecurityBacking.UNKNOWN)

    @RequiresApi(Build.VERSION_CODES.S)
    private fun mapSecurityLevelApi31(keyInfo: KeyInfo): SecurityBacking =
        when (keyInfo.securityLevel) {
            KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityBacking.STRONGBOX
            KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityBacking.TEE
            else -> SecurityBacking.UNKNOWN
        }

    override fun deleteKey(alias: String) {
        val ks = loadKeyStore()
        if (ks.containsAlias(alias)) {
            ks.deleteEntry(alias)
        }
    }

    private fun loadKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun isStrongBoxUnavailableCause(ex: Throwable): Boolean {
        var cur: Throwable? = ex
        while (cur != null) {
            if (cur is StrongBoxUnavailableException ||
                cur.javaClass.name.contains("StrongBox", ignoreCase = true)
            ) {
                return true
            }
            cur = cur.cause
        }
        return false
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}

/**
 * SharedPreferences-backed alias slot tracker keyed strictly by per-install salted SHA-256 account
 * hashes (mitigating brute-force reversal of low-entropy identifiers such as national IDs/CPFs).
 *
 * Host apps with Android Auto Backup enabled should exclude `maigbind_slots.xml` in
 * `data_extraction_rules.xml` / `backup_rules.xml`.
 */
internal class SharedPrefsKeyAliasSlotStore(
    context: Context,
) : KeyAliasSlotStore {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val saltLock = Any()

    override fun getOrCreateInstallSalt(): ByteArray {
        val existing = prefs.getString(KEY_INSTALL_SALT, null)
        if (existing != null) {
            return runCatching { Base64Url.decode(existing) }.getOrNull()?.takeIf { it.size == 32 }
                ?: generateAndStoreSalt()
        }
        return synchronized(saltLock) {
            val rechecked = prefs.getString(KEY_INSTALL_SALT, null)
            if (rechecked != null) {
                runCatching { Base64Url.decode(rechecked) }.getOrNull()?.takeIf { it.size == 32 }
                    ?: generateAndStoreSalt()
            } else {
                generateAndStoreSalt()
            }
        }
    }

    private fun generateAndStoreSalt(): ByteArray {
        val salt = ByteArray(32).also { SecureRandom().nextBytes(it) }
        prefs.edit().putString(KEY_INSTALL_SALT, Base64Url.encode(salt)).commit()
        return salt
    }

    override fun getActiveAlias(accountHash: String): String? = prefs.getString("active:$accountHash", null)

    override fun setActiveAlias(
        accountHash: String,
        alias: String?,
    ) {
        prefs
            .edit()
            .apply {
                if (alias == null) remove("active:$accountHash") else putString("active:$accountHash", alias)
            }.commit()
    }

    override fun getPendingAlias(accountHash: String): String? = prefs.getString("pending:$accountHash", null)

    override fun setPendingAlias(
        accountHash: String,
        alias: String?,
    ) {
        prefs
            .edit()
            .apply {
                if (alias == null) remove("pending:$accountHash") else putString("pending:$accountHash", alias)
            }.commit()
    }

    override fun promotePendingToActive(accountHash: String): Pair<String?, String?> {
        val pending = prefs.getString("pending:$accountHash", null) ?: return null to null
        val previousActive = prefs.getString("active:$accountHash", null)
        // Commit both updates in a single atomic transaction so a process crash cannot leave
        // active == pending and allow abortPendingEnrollment() to delete the active key.
        prefs
            .edit()
            .putString("active:$accountHash", pending)
            .remove("pending:$accountHash")
            .commit()
        return pending to previousActive
    }

    private companion object {
        const val PREFS_NAME = "maigbind_slots"
        const val KEY_INSTALL_SALT = "install_salt"
    }
}

/**
 * Production `androidx.biometric.BiometricPrompt` launcher strictly restricted to `BIOMETRIC_STRONG`.
 *
 * Note: Android throws `IllegalArgumentException` if `CryptoObject` is combined with `BIOMETRIC_WEAK`
 * or `DEVICE_CREDENTIAL`; only Class 3 strong biometrics are permitted.
 *
 * Reference: https://developer.android.com/training/sign-in/biometric-auth
 */
internal class PlatformBiometricPromptLauncher(
    private val appContext: Context,
) : BiometricPromptLauncher {
    override fun checkCapability(): BiometricCapability {
        val manager = BiometricManager.from(appContext)
        return when (manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG)) {
            BiometricManager.BIOMETRIC_SUCCESS -> BiometricCapability.READY_STRONG
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> BiometricCapability.NONE_ENROLLED
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> BiometricCapability.HARDWARE_UNAVAILABLE
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> BiometricCapability.NO_HARDWARE
            BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> BiometricCapability.SECURITY_UPDATE_REQUIRED
            else -> BiometricCapability.UNSUPPORTED
        }
    }

    override suspend fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String?,
        description: String?,
        negativeButtonText: String,
        signature: Signature,
    ): BiometricPromptOutcome =
        withContext(Dispatchers.Main.immediate) {
            suspendCancellableCoroutine { cont ->
                val executor = ContextCompat.getMainExecutor(activity)
                val callback =
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                            if (cont.isActive) {
                                cont.resume(BiometricPromptOutcome.Succeeded(result.cryptoObject?.signature))
                            }
                        }

                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence,
                        ) {
                            if (cont.isActive) {
                                cont.resume(BiometricPromptOutcome.Error(errorCode, errString.toString()))
                            }
                        }

                        override fun onAuthenticationFailed() {
                            // User can retry within the active prompt until max attempts / lockout.
                        }
                    }

                val prompt = BiometricPrompt(activity, executor, callback)
                val promptInfo =
                    BiometricPrompt.PromptInfo
                        .Builder()
                        .setTitle(title)
                        .apply {
                            if (!subtitle.isNullOrBlank()) setSubtitle(subtitle)
                            if (!description.isNullOrBlank()) setDescription(description)
                        }.setNegativeButtonText(negativeButtonText)
                        .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                        .build()

                cont.invokeOnCancellation {
                    prompt.cancelAuthentication()
                }

                prompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
            }
        }
}
