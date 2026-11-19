# MaigBind Attack Suite

This directory documents and automates adversary test cases derived from [THREAT_MODEL.md](../THREAT_MODEL.md).

## Threat-to-Verification Mapping

| Threat | Attack Vector | Automated Verification | Dynamic Frida Script |
|---|---|---|---|
| **T1** | Frida callback hook with `null` `CryptoObject` or swapped `Signature` | `MaigBindAndroidUnitTest.rejectsFridaHookReturningNullCryptoObjectOrSwappedSignature`, `AttackSuiteTest.forgedSoftwareKeySignatureAndRevokedBindingsAreRejectedByServer` | [bypass_biometric_callback.js](frida/bypass_biometric_callback.js) |
| **T2** | Client `if (success)` bypass | `MaigBindVerifierTest.fullRkpP384EnrollmentWithImmediatePopAndTransactionVerificationSucceeds` | — |
| **T3** | Root + leaked keybox / TrickyStore / unlocked bootloader | `MaigBindVerifierTest.rejectsRevokedKeyboxCertificate`, `AttackSuiteTest.detectsAndRejectsSuspiciousBurstKeyboxFanOut` | — |
| **T4** | Quarkslab Aug 11, 2026 attestation relay | `AttackSuiteTest.blocksOneShotOracleRelayViaTag709AndPendingPopGate` | [attestation_relay_hook.js](frida/attestation_relay_hook.js) |
| **T5** | Signature replay | `MaigBindVerifierTest.rejectsNonceReplayTamperedPayloadAndCrossDomainSignature`, `SampleServerTest` | — |
| **T6** | Post-signature tampering / Accessibility MITB | `MaigBindVerifierTest.rejectsNonceReplayTamperedPayloadAndCrossDomainSignature` | — |
| **T7** | New biometric enrolled on unlocked device | `MaigBindAndroidUnitTest.mapsNotEnrolledCancelledLockoutBiometryUnavailableAndInvalidation` | — |
| **T8** | Downgrade to `BIOMETRIC_WEAK` / PIN / software key | `MaigBindVerifierTest.rejectsWrongChallengeSoftwareLevelUnlockedBootAndWrongPackage`, `MaigBindAndroidUnitTest` | — |
| **T9** | Repackaged / cloned APK | `MaigBindVerifierTest.rejectsWrongChallengeSoftwareLevelUnlockedBootAndWrongPackage` | — |
| **T10** | Enrollment hijacking without step-up MFA | `SampleServerTest.endToEndHttpEnrollmentAndTransactionFlowAndAttackRejections` | — |

## Running the Automated Attack Suite

```bash
./gradlew :maigbind-verifier:test :maigbind-android:testDebugUnitTest :sample-server:test
```
