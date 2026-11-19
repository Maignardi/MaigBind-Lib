/**
 * MaigBind Attack Suite — Frida PoC: Quarkslab Attestation Relay Simulation (T4)
 *
 * Models the August 2026 Quarkslab attestation relay pattern:
 * intercepts `KeyGenParameterSpec.Builder.setAttestationChallenge` / `KeyStore.getCertificateChain`
 * on a rooted device and forwards the challenge to an attacker's clean oracle endpoint.
 *
 * Why MaigBind defeats one-shot relay:
 * 1. `attestationApplicationId` (Tag 709) rejects oracle apps with a different package/signature.
 * 2. Step-2 immediate Proof-of-Possession (`POST /enroll/confirm`) requires a live biometric-unlocked
 *    ECDSA signature from the newly attested private key before the server activates the binding.
 * 3. Every subsequent transaction requires a live biometric signature, turning a one-shot relay
 *    into an interactive online proxy requiring the genuine app + live biometrics on the clean device.
 *
 * Usage:
 *   frida -U -f io.github.maignardi.maigbind.sample.app -l attestation_relay_hook.js
 */
'use strict';

Java.perform(function () {
    const Builder = Java.use('android.security.keystore.KeyGenParameterSpec$Builder');
    const KeyStore = Java.use('java.security.KeyStore');
    const Base64 = Java.use('android.util.Base64');

    Builder.setAttestationChallenge.implementation = function (challengeBytes) {
        const b64 = Base64.encodeToString(challengeBytes, 11); // URL_SAFE | NO_PADDING | NO_WRAP
        console.log('[Frida-Relay] Captured server attestationChallenge=' + b64);
        console.log('[Frida-Relay] Note: Even if relayed to an oracle, MaigBind requires Step-2 PoP + Tag 709!');
        return this.setAttestationChallenge(challengeBytes);
    };

    KeyStore.getCertificateChain.implementation = function (alias) {
        const chain = this.getCertificateChain(alias);
        console.log('[Frida-Relay] getCertificateChain(' + alias + ') len=' + (chain ? chain.length : 0));
        return chain;
    };
});
