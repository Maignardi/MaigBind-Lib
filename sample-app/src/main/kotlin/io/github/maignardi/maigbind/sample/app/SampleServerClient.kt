package io.github.maignardi.maigbind.sample.app

import io.github.maignardi.maigbind.core.EnrollmentAttestResponse
import io.github.maignardi.maigbind.core.EnrollmentConfirmRequest
import io.github.maignardi.maigbind.core.EnrollmentConfirmResponse
import io.github.maignardi.maigbind.core.EnrollmentRequest
import io.github.maignardi.maigbind.core.SignedPayload
import io.github.maignardi.maigbind.core.VerificationVerdict
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

@Serializable
internal data class BeginEnrollBody(
    val accountId: String,
    val stepUpToken: String,
)

@Serializable
internal data class BeginEnrollResp(
    val challengeBase64Url: String,
    val issuedAt: Long,
    val expiresAt: Long,
)

@Serializable
internal data class TxChallengeBody(
    val accountId: String,
    val keyId: String,
)

@Serializable
internal data class TxChallengeResp(
    val nonceBase64Url: String,
    val issuedAt: Long,
    val expiresAt: Long,
)

@Serializable
internal data class ExecuteTransferBody(
    val accountId: String,
    val recipient: String,
    val amountCents: Long,
    val currency: String,
    val signedPayload: SignedPayload,
)

@Serializable
internal data class ExecuteTransferResp(
    val executed: Boolean,
    val transactionId: String? = null,
    val verdict: VerificationVerdict,
)

/**
 * Lightweight HTTP client talking to `sample-server` endpoints.
 */
internal class SampleServerClient(
    private val baseUrlProvider: () -> String,
    private val http: OkHttpClient = OkHttpClient(),
) {
    private val json =
        Json {
            ignoreUnknownKeys = true
            encodeDefaults = true
        }
    private val jsonMedia = "application/json; charset=utf-8".toMediaType()

    suspend fun beginEnrollment(
        accountId: String,
        stepUpToken: String,
    ): BeginEnrollResp = post("/enroll/begin", BeginEnrollBody(accountId, stepUpToken))

    suspend fun attestEnrollment(req: EnrollmentRequest): EnrollmentAttestResponse = post("/enroll/attest", req)

    suspend fun confirmEnrollment(req: EnrollmentConfirmRequest): EnrollmentConfirmResponse =
        post("/enroll/confirm", req)

    suspend fun issueTxChallenge(
        accountId: String,
        keyId: String,
    ): TxChallengeResp = post("/tx/challenge", TxChallengeBody(accountId, keyId))

    suspend fun executeTransfer(req: ExecuteTransferBody): ExecuteTransferResp = post("/tx/execute", req)

    private suspend inline fun <reified Req, reified Resp> post(
        path: String,
        body: Req,
    ): Resp =
        withContext(Dispatchers.IO) {
            val base = baseUrlProvider().trimEnd('/')
            val payload = json.encodeToString(body).toRequestBody(jsonMedia)
            val request =
                Request
                    .Builder()
                    .url("$base$path")
                    .post(payload)
                    .build()
            http.newCall(request).execute().use { response ->
                val text = response.body?.string().orEmpty()
                if (!response.isSuccessful && text.isBlank()) {
                    throw IllegalStateException("HTTP ${response.code} on $path")
                }
                if (response.code == 401 || response.code == 400 || response.code == 409) {
                    throw IllegalStateException("Server HTTP ${response.code}: $text")
                }
                json.decodeFromString<Resp>(text)
            }
        }
}
