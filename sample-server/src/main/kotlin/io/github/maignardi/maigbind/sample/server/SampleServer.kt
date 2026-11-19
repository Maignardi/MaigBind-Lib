package io.github.maignardi.maigbind.sample.server

import io.github.maignardi.maigbind.core.EnrollmentConfirmRequest
import io.github.maignardi.maigbind.core.EnrollmentRequest
import io.github.maignardi.maigbind.core.SignedPayload
import io.github.maignardi.maigbind.core.VerificationVerdict
import io.github.maignardi.maigbind.core.canonical
import io.github.maignardi.maigbind.core.canonicalFields
import io.github.maignardi.maigbind.verifier.MaigBindVerifier
import io.ktor.http.HttpStatusCode
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.install
import io.ktor.server.engine.embeddedServer
import io.ktor.server.netty.Netty
import io.ktor.server.plugins.calllogging.CallLogging
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import io.ktor.server.plugins.statuspages.StatusPages
import io.ktor.server.request.receive
import io.ktor.server.response.respond
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.routing
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.util.UUID

@Serializable
public data class BeginEnrollHttpRequest(
    val accountId: String,
    /** Integrator-verified step-up MFA / eKYC assertion required to mitigate enrollment hijacking (T10). */
    val stepUpToken: String,
)

@Serializable
public data class BeginEnrollHttpResponse(
    val challengeBase64Url: String,
    val issuedAt: Long,
    val expiresAt: Long,
)

@Serializable
public data class TxChallengeHttpRequest(
    val accountId: String,
    val keyId: String,
)

@Serializable
public data class TxChallengeHttpResponse(
    val nonceBase64Url: String,
    val issuedAt: Long,
    val expiresAt: Long,
)

@Serializable
public data class ExecuteTransferHttpRequest(
    val accountId: String,
    val recipient: String,
    val amountCents: Long,
    val currency: String,
    val signedPayload: SignedPayload,
)

@Serializable
public data class ExecuteTransferHttpResponse(
    val executed: Boolean,
    val transactionId: String? = null,
    val verdict: VerificationVerdict,
)

@Serializable
public data class ErrorHttpResponse(
    val error: String,
)

@Serializable
public data class RevokeBindingHttpRequest(
    val bindingId: String? = null,
    val accountId: String? = null,
)

@Serializable
public data class RevokeBindingHttpResponse(
    val revokedCount: Int,
)

@Serializable
public data class ActiveBindingHttpResponse(
    val accountId: String,
    val activeKeyId: String? = null,
    val bindingId: String? = null,
)

public const val DEMO_VALID_STEP_UP_TOKEN: String = "stepup-mfa-verified"

/**
 * Configures the Ktor routing and JSON serialization for the MaigBind sample banking server.
 */
public fun Application.configureSampleServer(
    verifier: MaigBindVerifier = MaigBindVerifier(),
    stepUpValidator: (String) -> Boolean = { it == DEMO_VALID_STEP_UP_TOKEN },
) {
    install(ContentNegotiation) {
        json(
            Json {
                ignoreUnknownKeys = true
                encodeDefaults = true
            },
        )
    }
    install(CallLogging)
    install(StatusPages) {
        exception<IllegalArgumentException> { call, cause ->
            call.respond(HttpStatusCode.BadRequest, ErrorHttpResponse(cause.message ?: "Bad request"))
        }
        exception<IllegalStateException> { call, cause ->
            call.respond(HttpStatusCode.Conflict, ErrorHttpResponse(cause.message ?: "Conflict"))
        }
    }

    routing {
        get("/health") {
            call.respond(mapOf("status" to "ok"))
        }
        enrollmentRoutes(verifier, stepUpValidator)
        transactionRoutes(verifier)
    }
}

private fun Route.enrollmentRoutes(
    verifier: MaigBindVerifier,
    stepUpValidator: (String) -> Boolean,
) {
    post("/enroll/begin") {
        val body = call.receive<BeginEnrollHttpRequest>()
        if (!stepUpValidator(body.stepUpToken)) {
            call.respond(
                HttpStatusCode.Unauthorized,
                ErrorHttpResponse("Step-up MFA authentication required before device binding"),
            )
            return@post
        }
        val ch = verifier.beginEnrollment(body.accountId)
        call.respond(
            BeginEnrollHttpResponse(
                challengeBase64Url = ch.challengeBase64Url,
                issuedAt = ch.issuedAt,
                expiresAt = ch.expiresAt,
            ),
        )
    }

    post("/enroll/attest") {
        val req = call.receive<EnrollmentRequest>()
        val resp = verifier.verifyEnrollmentAttestation(req)
        val status = if (resp.verdict.isVerified) HttpStatusCode.OK else HttpStatusCode.Forbidden
        call.respond(status, resp)
    }

    post("/enroll/confirm") {
        val req = call.receive<EnrollmentConfirmRequest>()
        val resp = verifier.confirmEnrollmentPop(req)
        val status = if (resp.verdict.isVerified) HttpStatusCode.OK else HttpStatusCode.Forbidden
        call.respond(status, resp)
    }

    post("/bindings/revoke") {
        val req = call.receive<RevokeBindingHttpRequest>()
        val revoked =
            when {
                !req.bindingId.isNullOrBlank() -> if (verifier.revokeBinding(req.bindingId)) 1 else 0
                !req.accountId.isNullOrBlank() -> verifier.revokeAccountBindings(req.accountId)
                else -> throw IllegalArgumentException("Either bindingId or accountId must be provided")
            }
        call.respond(HttpStatusCode.OK, RevokeBindingHttpResponse(revokedCount = revoked))
    }

    get("/bindings/active") {
        val accountId =
            call.request.queryParameters["accountId"]?.takeIf { it.isNotBlank() }
                ?: throw IllegalArgumentException("Query parameter 'accountId' is required")
        val active = verifier.getActiveBindings(accountId).firstOrNull()
        call.respond(
            HttpStatusCode.OK,
            ActiveBindingHttpResponse(
                accountId = accountId,
                activeKeyId = active?.keyId,
                bindingId = active?.bindingId,
            ),
        )
    }
}

private fun Route.transactionRoutes(verifier: MaigBindVerifier) {
    post("/tx/challenge") {
        val req = call.receive<TxChallengeHttpRequest>()
        val ch = verifier.issueTransactionNonce(req.accountId, req.keyId)
        call.respond(
            TxChallengeHttpResponse(
                nonceBase64Url = ch.nonceBase64Url,
                issuedAt = ch.issuedAt,
                expiresAt = ch.expiresAt,
            ),
        )
    }

    post("/tx/execute") {
        val req = call.receive<ExecuteTransferHttpRequest>()
        val expectedFields =
            canonicalFields(
                "amountCents" to canonical(req.amountCents),
                "currency" to canonical(req.currency),
                "recipient" to canonical(req.recipient),
            )
        val verdict =
            verifier.verifyTransaction(
                accountId = req.accountId,
                signedPayload = req.signedPayload,
                expectedOperationType = "PIX_TRANSFER",
                expectedFields = expectedFields,
            )
        val status = if (verdict.isVerified) HttpStatusCode.OK else HttpStatusCode.Forbidden
        call.respond(
            status,
            ExecuteTransferHttpResponse(
                executed = verdict.isVerified,
                transactionId = if (verdict.isVerified) "tx-${UUID.randomUUID()}" else null,
                verdict = verdict,
            ),
        )
    }
}

public fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0") {
        configureSampleServer()
    }.start(wait = true)
}
