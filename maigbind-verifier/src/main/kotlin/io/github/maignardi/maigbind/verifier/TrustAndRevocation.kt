package io.github.maignardi.maigbind.verifier

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.ByteArrayInputStream
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.time.Clock
import java.time.Duration
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

/** Official Google endpoint publishing both the legacy RSA root and the April 2026 RKP ECDSA P-384 root. */
public const val GOOGLE_ATTESTATION_ROOT_URL: String = "https://android.googleapis.com/attestation/root"

/** Official Google endpoint publishing revoked and suspended attestation certificate serials. */
public const val GOOGLE_ATTESTATION_STATUS_URL: String = "https://android.googleapis.com/attestation/status"

/** Origin of loaded root trust anchors. */
public enum class TrustStoreSource {
    REMOTE,
    CACHED,
    EMBEDDED_FALLBACK,
    UNAVAILABLE,
}

/** Result returned by [TrustStoreProvider.getTrustedRoots]. */
public data class TrustRootsSnapshot(
    val roots: List<X509Certificate>,
    val source: TrustStoreSource,
    val failureReason: String? = null,
)

/** Abstraction for loading Google Hardware Attestation root certificates. */
public interface TrustStoreProvider {
    public fun getTrustedRoots(): TrustRootsSnapshot
}

/** Outcome of checking a certificate chain against the attestation revocation list. */
public sealed class RevocationCheckResult {
    public data object Clear : RevocationCheckResult()

    public data class Revoked(
        val serialKey: String,
        val status: String,
        val reason: String?,
    ) : RevocationCheckResult()

    public data class Unavailable(
        val error: String,
    ) : RevocationCheckResult()
}

/** Abstraction for checking certificate revocation status. */
public interface RevocationStatusProvider {
    public fun checkChain(certificates: List<X509Certificate>): RevocationCheckResult
}

/**
 * Embedded official Google attestation roots fetched from `https://android.googleapis.com/attestation/root`:
 * 1. Legacy Google Hardware Attestation Root (RSA-4096, serial `f92009e853b6b045`)
 * 2. Google RKP Key Attestation CA1 (ECDSA P-384, mandatory for RKP devices as of April 10, 2026)
 *
 * Reference: https://developer.android.com/privacy-and-security/security-key-attestation
 */
public object EmbeddedGoogleRoots {
    public const val LEGACY_RSA_ROOT_PEM: String =
        "-----BEGIN CERTIFICATE-----\n" +
            "MIIFHDCCAwSgAwIBAgIJAPHBcqaZ6vUdMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV\n" +
            "BAUTEGY5MjAwOWU4NTNiNmIwNDUwHhcNMjIwMzIwMTgwNzQ4WhcNNDIwMzE1MTgw\n" +
            "NzQ4WjAbMRkwFwYDVQQFExBmOTIwMDllODUzYjZiMDQ1MIICIjANBgkqhkiG9w0B\n" +
            "AQEFAAOCAg8AMIICCgKCAgEAr7bHgiuxpwHsK7Qui8xUFmOr75gvMsd/dTEDDJdS\n" +
            "Sxtf6An7xyqpRR90PL2abxM1dEqlXnf2tqw1Ne4Xwl5jlRfdnJLmN0pTy/4lj4/7\n" +
            "tv0Sk3iiKkypnEUtR6WfMgH0QZfKHM1+di+y9TFRtv6y//0rb+T+W8a9nsNL/ggj\n" +
            "nar86461qO0rOs2cXjp3kOG1FEJ5MVmFmBGtnrKpa73XpXyTqRxB/M0n1n/W9nGq\n" +
            "C4FSYa04T6N5RIZGBN2z2MT5IKGbFlbC8UrW0DxW7AYImQQcHtGl/m00QLVWutHQ\n" +
            "oVJYnFPlXTcHYvASLu+RhhsbDmxMgJJ0mcDpvsC4PjvB+TxywElgS70vE0XmLD+O\n" +
            "JtvsBslHZvPBKCOdT0MS+tgSOIfga+z1Z1g7+DVagf7quvmag8jfPioyKvxnK/Eg\n" +
            "sTUVi2ghzq8wm27ud/mIM7AY2qEORR8Go3TVB4HzWQgpZrt3i5MIlCaY504LzSRi\n" +
            "igHCzAPlHws+W0rB5N+er5/2pJKnfBSDiCiFAVtCLOZ7gLiMm0jhO2B6tUXHI/+M\n" +
            "RPjy02i59lINMRRev56GKtcd9qO/0kUJWdZTdA2XoS82ixPvZtXQpUpuL12ab+9E\n" +
            "aDK8Z4RHJYYfCT3Q5vNAXaiWQ+8PTWm2QgBR/bkwSWc+NpUFgNPN9PvQi8WEg5Um\n" +
            "AGMCAwEAAaNjMGEwHQYDVR0OBBYEFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMB8GA1Ud\n" +
            "IwQYMBaAFDZh4QB8iAUJUYtEbEf/GkzJ6k8SMA8GA1UdEwEB/wQFMAMBAf8wDgYD\n" +
            "VR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4ICAQB8cMqTllHc8U+qCrOlg3H7\n" +
            "174lmaCsbo/bJ0C17JEgMLb4kvrqsXZs01U3mB/qABg/1t5Pd5AORHARs1hhqGIC\n" +
            "W/nKMav574f9rZN4PC2ZlufGXb7sIdJpGiO9ctRhiLuYuly10JccUZGEHpHSYM2G\n" +
            "tkgYbZba6lsCPYAAP83cyDV+1aOkTf1RCp/lM0PKvmxYN10RYsK631jrleGdcdkx\n" +
            "oSK//mSQbgcWnmAEZrzHoF1/0gso1HZgIn0YLzVhLSA/iXCX4QT2h3J5z3znluKG\n" +
            "1nv8NQdxei2DIIhASWfu804CA96cQKTTlaae2fweqXjdN1/v2nqOhngNyz1361mF\n" +
            "mr4XmaKH/ItTwOe72NI9ZcwS1lVaCvsIkTDCEXdm9rCNPAY10iTunIHFXRh+7KPz\n" +
            "lHGewCq/8TOohBRn0/NNfh7uRslOSZ/xKbN9tMBtw37Z8d2vvnXq/YWdsm1+JLVw\n" +
            "n6yYD/yacNJBlwpddla8eaVMjsF6nBnIgQOf9zKSe06nSTqvgwUHosgOECZJZ1Eu\n" +
            "zbH4yswbt02tKtKEFhx+v+OTge/06V+jGsqTWLsfrOCNLuA8H++z+pUENmpqnnHo\n" +
            "vaI47gC+TNpkgYGkkBT6B/m/U01BuOBBTzhIlMEZq9qkDWuM2cA5kW5V3FJUcfHn\n" +
            "w1IdYIg2Wxg7yHcQZemFQg==\n" +
            "-----END CERTIFICATE-----"

    public const val RKP_ECDSA_P384_ROOT_PEM: String =
        "-----BEGIN CERTIFICATE-----\n" +
            "MIICIjCCAaigAwIBAgIRAISp0Cl7DrWK5/8OgN52BgUwCgYIKoZIzj0EAwMwUjEc\n" +
            "MBoGA1UEAwwTS2V5IEF0dGVzdGF0aW9uIENBMTEQMA4GA1UECwwHQW5kcm9pZDET\n" +
            "MBEGA1UECgwKR29vZ2xlIExMQzELMAkGA1UEBhMCVVMwHhcNMjUwNzE3MjIzMjE4\n" +
            "WhcNMzUwNzE1MjIzMjE4WjBSMRwwGgYDVQQDDBNLZXkgQXR0ZXN0YXRpb24gQ0Ex\n" +
            "MRAwDgYDVQQLDAdBbmRyb2lkMRMwEQYDVQQKDApHb29nbGUgTExDMQswCQYDVQQG\n" +
            "EwJVUzB2MBAGByqGSM49AgEGBSuBBAAiA2IABCPaI3FO3z5bBQo8cuiEas4HjqCt\n" +
            "G/mLFfRT0MsIssPBEEU5Cfbt6sH5yOAxqEi5QagpU1yX4HwnGb7OtBYpDTB57uH5\n" +
            "Eczm34A5FNijV3s0/f0UPl7zbJcTx6xwqMIRq6NCMEAwDwYDVR0TAQH/BAUwAwEB\n" +
            "/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFFIyuyz7RkOb3NaBqQ5lZuA0QepA\n" +
            "MAoGCCqGSM49BAMDA2gAMGUCMETfjPO/HwqReR2CS7p0ZWoD/LHs6hDi422opifH\n" +
            "EUaYLxwGlT9SLdjkVpz0UUOR5wIxAIoGyxGKRHVTpqpGRFiJtQEOOTp/+s1GcxeY\n" +
            "uR2zh/80lQyu9vAFCj6E4AXc+osmRg==\n" +
            "-----END CERTIFICATE-----"

    public fun loadFallbackCertificates(): List<X509Certificate> =
        listOf(LEGACY_RSA_ROOT_PEM, RKP_ECDSA_P384_ROOT_PEM).map(::parsePemCertificate)

    public fun isRkpRoot(certificate: X509Certificate): Boolean {
        val pub = certificate.publicKey
        if (pub is ECPublicKey && pub.params.curve.field.fieldSize >= 384) {
            return true
        }
        return certificate.subjectX500Principal.name.contains("Key Attestation CA1", ignoreCase = true)
    }
}

internal fun parsePemCertificate(pem: String): X509Certificate {
    val factory = CertificateFactory.getInstance("X.509")
    return factory.generateCertificate(ByteArrayInputStream(pem.encodeToByteArray())) as X509Certificate
}

/**
 * Fetches Google's attestation roots from [rootUrl] with TTL caching and embedded dual-root
 * fallback (both Legacy RSA and RKP ECDSA P-384).
 */
public class GoogleTrustStoreProvider(
    private val rootUrl: String = GOOGLE_ATTESTATION_ROOT_URL,
    private val cacheTtl: Duration = Duration.ofHours(6),
    private val allowEmbeddedFallback: Boolean = true,
    private val clock: Clock = Clock.systemUTC(),
    private val httpClient: HttpClient =
        HttpClient
            .newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build(),
) : TrustStoreProvider {
    private val lock = ReentrantLock()
    private val json = Json { ignoreUnknownKeys = true }
    private var cachedRoots: List<X509Certificate>? = null
    private var cachedAtMillis: Long = 0L

    override fun getTrustedRoots(): TrustRootsSnapshot =
        lock.withLock {
            val now = clock.millis()
            val current = cachedRoots
            if (current != null && (now - cachedAtMillis) < cacheTtl.toMillis()) {
                return TrustRootsSnapshot(current, TrustStoreSource.CACHED)
            }

            val fetchResult =
                runCatching {
                    val request =
                        HttpRequest
                            .newBuilder(URI.create(rootUrl))
                            .timeout(Duration.ofSeconds(5))
                            .GET()
                            .build()
                    val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())
                    require(response.statusCode() in 200..299) {
                        "HTTP ${response.statusCode()} from $rootUrl"
                    }
                    val pemList = json.decodeFromString<List<String>>(response.body())
                    require(pemList.isNotEmpty()) { "Empty root certificate list from $rootUrl" }
                    pemList.map(::parsePemCertificate)
                }

            return fetchResult.fold(
                onSuccess = { freshRoots ->
                    cachedRoots = freshRoots
                    cachedAtMillis = now
                    TrustRootsSnapshot(freshRoots, TrustStoreSource.REMOTE)
                },
                onFailure = { ex ->
                    when {
                        current != null ->
                            TrustRootsSnapshot(
                                roots = current,
                                source = TrustStoreSource.CACHED,
                                failureReason = ex.message,
                            )
                        allowEmbeddedFallback ->
                            TrustRootsSnapshot(
                                roots = EmbeddedGoogleRoots.loadFallbackCertificates(),
                                source = TrustStoreSource.EMBEDDED_FALLBACK,
                                failureReason = ex.message,
                            )
                        else ->
                            TrustRootsSnapshot(
                                roots = emptyList(),
                                source = TrustStoreSource.UNAVAILABLE,
                                failureReason = ex.message ?: ex::class.simpleName,
                            )
                    }
                },
            )
        }
}

/** Static trust store provider useful for deterministic unit tests and custom CAs. */
public class StaticTrustStoreProvider(
    private val roots: List<X509Certificate>,
) : TrustStoreProvider {
    override fun getTrustedRoots(): TrustRootsSnapshot = TrustRootsSnapshot(roots, TrustStoreSource.EMBEDDED_FALLBACK)
}

@Serializable
internal data class StatusFeedResponse(
    val entries: Map<String, StatusFeedEntry> = emptyMap(),
)

@Serializable
internal data class StatusFeedEntry(
    val status: String,
    val reason: String? = null,
    val expires: String? = null,
    val comment: String? = null,
)

/**
 * Fetches and caches Google's attestation certificate revocation list from
 * `https://android.googleapis.com/attestation/status`.
 *
 * Note: Live responses from Google's status feed contain serial numbers formatted as either
 * base-10 decimal strings or lowercase hexadecimal strings; both representations are checked.
 */
public class GoogleRevocationStatusProvider(
    private val statusUrl: String = GOOGLE_ATTESTATION_STATUS_URL,
    private val cacheTtl: Duration = Duration.ofHours(1),
    private val clock: Clock = Clock.systemUTC(),
    private val httpClient: HttpClient =
        HttpClient
            .newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build(),
) : RevocationStatusProvider {
    private val lock = ReentrantLock()
    private val json = Json { ignoreUnknownKeys = true }
    private var cachedEntries: Map<String, StatusFeedEntry>? = null
    private var cachedAtMillis: Long = 0L

    override fun checkChain(certificates: List<X509Certificate>): RevocationCheckResult {
        val entries =
            loadEntries() ?: return RevocationCheckResult.Unavailable(
                "Unable to load attestation revocation list from $statusUrl",
            )
        return checkCertificatesAgainstEntries(certificates, entries)
    }

    private fun loadEntries(): Map<String, StatusFeedEntry>? =
        lock.withLock {
            val now = clock.millis()
            val current = cachedEntries
            if (current != null && (now - cachedAtMillis) < cacheTtl.toMillis()) {
                return current
            }

            val fetched =
                runCatching {
                    val request =
                        HttpRequest
                            .newBuilder(URI.create(statusUrl))
                            .timeout(Duration.ofSeconds(5))
                            .GET()
                            .build()
                    val response = httpClient.send(request, HttpResponse.BodyHandlers.ofString())
                    require(response.statusCode() in 200..299) {
                        "HTTP ${response.statusCode()} from $statusUrl"
                    }
                    val parsed = json.decodeFromString<StatusFeedResponse>(response.body())
                    parsed.entries.mapKeys { (k, _) -> k.lowercase() }
                }

            return fetched
                .getOrElse {
                    current
                }?.also { loaded ->
                    if (fetched.isSuccess) {
                        cachedEntries = loaded
                        cachedAtMillis = now
                    }
                }
        }

    internal companion object {
        fun checkCertificatesAgainstEntries(
            certificates: List<X509Certificate>,
            entries: Map<String, StatusFeedEntry>,
        ): RevocationCheckResult {
            for (cert in certificates) {
                val serial = cert.serialNumber
                val candidates =
                    listOf(
                        serial.toString(10),
                        serial.toString(16).lowercase(),
                    )
                for (candidate in candidates) {
                    val hit = entries[candidate]
                    if (hit != null && (hit.status == "REVOKED" || hit.status == "SUSPENDED")) {
                        return RevocationCheckResult.Revoked(
                            serialKey = candidate,
                            status = hit.status,
                            reason = hit.reason,
                        )
                    }
                }
            }
            return RevocationCheckResult.Clear
        }
    }
}

/** In-memory revocation provider for deterministic testing and offline validation suites. */
public class StaticRevocationStatusProvider(
    private val revokedSerials: Map<String, Pair<String, String?>> = emptyMap(),
    private val simulateUnavailable: Boolean = false,
) : RevocationStatusProvider {
    override fun checkChain(certificates: List<X509Certificate>): RevocationCheckResult {
        if (simulateUnavailable) {
            return RevocationCheckResult.Unavailable("Simulated revocation feed outage")
        }
        val entries =
            revokedSerials
                .mapKeys { it.key.lowercase() }
                .mapValues { (_, pair) -> StatusFeedEntry(status = pair.first, reason = pair.second) }
        return GoogleRevocationStatusProvider.checkCertificatesAgainstEntries(certificates, entries)
    }
}
