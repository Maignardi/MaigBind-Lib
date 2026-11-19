package io.github.maignardi.maigbind.sample.app

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import io.github.maignardi.maigbind.android.BiometricCapability
import io.github.maignardi.maigbind.android.MaigBind
import io.github.maignardi.maigbind.core.MaigBindError
import io.github.maignardi.maigbind.core.MaigBindResult
import io.github.maignardi.maigbind.core.PromptText
import io.github.maignardi.maigbind.core.TransactionPayload
import io.github.maignardi.maigbind.core.canonical
import io.github.maignardi.maigbind.core.canonicalFields
import kotlinx.coroutines.launch

/**
 * Sample Compose activity demonstrating MaigBind two-step enrollment (Attestation + Biometric PoP)
 * and hardware-signed financial transfers.
 */
public class MainActivity : FragmentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val maigBind = MaigBind(applicationContext)
        setContent {
            MaterialTheme {
                MaigBindDemoScreen(
                    biometricCapability = maigBind.getBiometricCapability(),
                    hasEnrolledKey = { accountId -> maigBind.hasEnrolledKey(accountId) },
                    getKeyId = { accountId -> maigBind.getEnrolledKeyId(accountId) },
                    onEnroll = { accountId, serverUrl, stepUpToken, log ->
                        runEnrollmentFlow(this, maigBind, accountId, serverUrl, stepUpToken, log)
                    },
                    onTransfer = { accountId, serverUrl, recipient, amountCents, log ->
                        runTransferFlow(this, maigBind, accountId, serverUrl, recipient, amountCents, log)
                    },
                    onUnenroll = { accountId -> maigBind.unenroll(accountId) },
                )
            }
        }
    }

    private suspend fun runEnrollmentFlow(
        activity: FragmentActivity,
        maigBind: MaigBind,
        accountId: String,
        serverUrl: String,
        stepUpToken: String,
        log: (String) -> Unit,
    ) {
        val api = SampleServerClient({ serverUrl })
        runCatching {
            log("1/4 Requesting enrollment challenge (step-up MFA token)...")
            val ch = api.beginEnrollment(accountId, stepUpToken)

            log("2/4 Generating hardware-backed P-256 key + attestation chain...")
            val enrollReq =
                when (val res = maigBind.enroll(accountId, ch.challengeBase64Url)) {
                    is MaigBindResult.Failure -> {
                        log("Client enroll failed: ${res.error.message}")
                        return
                    }
                    is MaigBindResult.Success -> res.value
                }
            log("Key generated in ${enrollReq.securityBacking} (keyId=${enrollReq.keyId.take(12)}...)")

            log("3/4 Submitting attestation chain to sample-server...")
            val attestResp = api.attestEnrollment(enrollReq)
            if (!attestResp.verdict.isVerified) {
                val codes = attestResp.verdict.findings.joinToString { "${it.code}:${it.message}" }
                log("Server rejected attestation (${attestResp.verdict.status}): $codes")
                return
            }

            log("4/4 Prompting Strong Biometrics for immediate Proof-of-Possession...")
            val popReq =
                when (
                    val res =
                        maigBind.confirmEnrollmentPop(
                            activity = activity,
                            bindingId = attestResp.bindingId,
                            accountId = accountId,
                            popChallengeBase64Url = attestResp.popChallengeBase64Url,
                            issuedAt = System.currentTimeMillis(),
                            expiresAt = attestResp.popExpiresAt,
                            promptText =
                                PromptText(
                                    title = "Bind This Device",
                                    subtitle = "Account: $accountId",
                                    description = "Confirm with biometrics to activate hardware key binding",
                                ),
                        )
                ) {
                    is MaigBindResult.Failure -> {
                        log("PoP biometric failed: ${res.error.message}")
                        return
                    }
                    is MaigBindResult.Success -> res.value
                }

            val confirmResp = api.confirmEnrollment(popReq)
            log("Enrollment status: ${confirmResp.status} (${confirmResp.verdict.status})")
        }.onFailure { ex ->
            log("Enrollment error: ${ex.message}")
        }
    }

    private suspend fun runTransferFlow(
        activity: FragmentActivity,
        maigBind: MaigBind,
        accountId: String,
        serverUrl: String,
        recipient: String,
        amountCents: Long,
        log: (String) -> Unit,
    ) {
        val api = SampleServerClient({ serverUrl })
        runCatching {
            val keyId = maigBind.getEnrolledKeyId(accountId)
            if (keyId == null) {
                log("NotEnrolled: Please bind this device first.")
                return
            }
            log("1/3 Requesting single-use nonce from server...")
            val ch = api.issueTxChallenge(accountId, keyId)

            val payload =
                TransactionPayload(
                    keyId = keyId,
                    operationType = "PIX_TRANSFER",
                    nonce = ch.nonceBase64Url,
                    issuedAt = ch.issuedAt,
                    expiresAt = ch.expiresAt,
                    fields =
                        canonicalFields(
                            "amountCents" to canonical(amountCents),
                            "currency" to canonical("BRL"),
                            "recipient" to canonical(recipient),
                        ),
                )

            log("2/3 Prompting BiometricPrompt + CryptoObject(Signature)...")
            val formattedAmount = "%.2f".format(amountCents / 100.0)
            val signed =
                when (
                    val res =
                        maigBind.sign(
                            activity = activity,
                            accountId = accountId,
                            payload = payload,
                            promptText =
                                PromptText(
                                    title = "Confirm Transfer",
                                    subtitle = "BRL $formattedAmount to $recipient",
                                    description = "Signed in secure hardware (MaigBind v1)",
                                ),
                        )
                ) {
                    is MaigBindResult.Failure -> {
                        val hint =
                            if (res.error is MaigBindError.NeedsReEnrollment) {
                                " -> Biometrics changed! Re-enrollment required."
                            } else {
                                ""
                            }
                        log("Signing failed (${res.error::class.simpleName}): ${res.error.message}$hint")
                        return
                    }
                    is MaigBindResult.Success -> res.value
                }

            log("3/3 Submitting SignedPayload to server for verification...")
            val resp =
                api.executeTransfer(
                    ExecuteTransferBody(
                        accountId = accountId,
                        recipient = recipient,
                        amountCents = amountCents,
                        currency = "BRL",
                        signedPayload = signed,
                    ),
                )
            val codes = resp.verdict.findings.joinToString { it.code.name }
            log("Server response: executed=${resp.executed}, verdict=${resp.verdict.status}, findings=[$codes]")
        }.onFailure { ex ->
            log("Transfer error: ${ex.message}")
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
public fun MaigBindDemoScreen(
    biometricCapability: BiometricCapability,
    hasEnrolledKey: suspend (String) -> Boolean,
    getKeyId: suspend (String) -> String?,
    onEnroll: suspend (accountId: String, serverUrl: String, stepUpToken: String, log: (String) -> Unit) -> Unit,
    onTransfer: suspend (
        accountId: String,
        serverUrl: String,
        recipient: String,
        amountCents: Long,
        log: (String) -> Unit,
    ) -> Unit,
    onUnenroll: suspend (String) -> MaigBindResult<Unit>,
) {
    val scope = rememberCoroutineScope()
    var serverUrl by remember { mutableStateOf("http://10.0.2.2:8080") }
    var accountId by remember { mutableStateOf("acct-demo-01") }
    var stepUpToken by remember { mutableStateOf("stepup-mfa-verified") }
    var recipient by remember { mutableStateOf("alice@pix.br") }
    var amountText by remember { mutableStateOf("15000") }
    var enrolled by remember { mutableStateOf(false) }
    var currentKeyId by remember { mutableStateOf<String?>(null) }
    var logs by remember { mutableStateOf("Ready.") }

    suspend fun refreshStatus() {
        enrolled = hasEnrolledKey(accountId)
        currentKeyId = getKeyId(accountId)
    }

    LaunchedEffect(accountId) {
        refreshStatus()
    }

    Scaffold(
        topBar = { TopAppBar(title = { Text("MaigBind Security Demo") }) },
    ) { padding ->
        Column(
            modifier =
                Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(16.dp)
                    .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            DeviceBindingCard(
                biometricCapability = biometricCapability,
                enrolled = enrolled,
                currentKeyId = currentKeyId,
                serverUrl = serverUrl,
                onServerUrlChange = { serverUrl = it },
                accountId = accountId,
                onAccountIdChange = { accountId = it },
                stepUpToken = stepUpToken,
                onStepUpTokenChange = { stepUpToken = it },
                onEnrollClick = {
                    scope.launch {
                        logs = ""
                        onEnroll(accountId, serverUrl, stepUpToken) { line ->
                            logs = if (logs.isEmpty()) line else "$logs\n$line"
                        }
                        refreshStatus()
                    }
                },
                onUnenrollClick = {
                    scope.launch {
                        onUnenroll(accountId)
                        refreshStatus()
                        logs = "Unenrolled key for $accountId"
                    }
                },
            )
            TransferCard(
                recipient = recipient,
                onRecipientChange = { recipient = it },
                amountText = amountText,
                onAmountChange = { amountText = it },
                onTransferClick = {
                    val cents = amountText.toLongOrNull() ?: 0L
                    scope.launch {
                        logs = ""
                        onTransfer(accountId, serverUrl, recipient, cents) { line ->
                            logs = if (logs.isEmpty()) line else "$logs\n$line"
                        }
                        refreshStatus()
                    }
                },
            )
            AuditLogCard(logs = logs)
        }
    }
}

@Composable
private fun DeviceBindingCard(
    biometricCapability: BiometricCapability,
    enrolled: Boolean,
    currentKeyId: String?,
    serverUrl: String,
    onServerUrlChange: (String) -> Unit,
    accountId: String,
    onAccountIdChange: (String) -> Unit,
    stepUpToken: String,
    onStepUpTokenChange: (String) -> Unit,
    onEnrollClick: () -> Unit,
    onUnenrollClick: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Device Binding Status", style = MaterialTheme.typography.titleMedium)
            Text("Biometric capability: $biometricCapability")
            Text("Enrolled: $enrolled")
            if (currentKeyId != null) {
                Text("Key ID: ${currentKeyId.take(20)}...", fontFamily = FontFamily.Monospace)
            }
            OutlinedTextField(
                value = serverUrl,
                onValueChange = onServerUrlChange,
                label = { Text("Server URL") },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = accountId,
                onValueChange = onAccountIdChange,
                label = { Text("Account ID") },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = stepUpToken,
                onValueChange = onStepUpTokenChange,
                label = { Text("Step-Up MFA Token") },
                modifier = Modifier.fillMaxWidth(),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = onEnrollClick) {
                    Text("Enroll Device")
                }
                OutlinedButton(onClick = onUnenrollClick) {
                    Text("Unenroll")
                }
            }
        }
    }
}

@Composable
private fun TransferCard(
    recipient: String,
    onRecipientChange: (String) -> Unit,
    amountText: String,
    onAmountChange: (String) -> Unit,
    onTransferClick: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Signed Sensitive Transfer", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                value = recipient,
                onValueChange = onRecipientChange,
                label = { Text("Recipient") },
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = amountText,
                onValueChange = onAmountChange,
                label = { Text("Amount (cents)") },
                modifier = Modifier.fillMaxWidth(),
            )
            Button(onClick = onTransferClick) {
                Text("Sign & Execute Transfer")
            }
        }
    }
}

@Composable
private fun AuditLogCard(logs: String) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text("Protocol & Audit Log", style = MaterialTheme.typography.titleMedium)
            Spacer(modifier = Modifier.height(6.dp))
            Text(logs, fontFamily = FontFamily.Monospace)
        }
    }
}
