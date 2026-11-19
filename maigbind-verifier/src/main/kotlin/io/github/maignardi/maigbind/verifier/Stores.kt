package io.github.maignardi.maigbind.verifier

import io.github.maignardi.maigbind.core.EnrollmentStatus
import io.github.maignardi.maigbind.core.SecurityBacking
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/** Single-use server challenge store for enrollment attestation and Proof-of-Possession. */
public interface ChallengeStore {
    public fun saveChallenge(
        key: String,
        challenge: ByteArray,
        expiresAtMillis: Long,
    )

    /**
     * Atomically verifies and consumes [challenge] for [key] if present and unexpired.
     */
    public fun consumeChallenge(
        key: String,
        challenge: ByteArray,
        nowMillis: Long,
    ): Boolean
}

/** Thread-safe in-memory [ChallengeStore] suitable for single-node deployments and testing. */
public class InMemoryChallengeStore : ChallengeStore {
    private data class Entry(
        val challenge: ByteArray,
        val expiresAtMillis: Long,
    )

    private val map = ConcurrentHashMap<String, Entry>()

    override fun saveChallenge(
        key: String,
        challenge: ByteArray,
        expiresAtMillis: Long,
    ) {
        map[key] = Entry(challenge.copyOf(), expiresAtMillis)
    }

    override fun consumeChallenge(
        key: String,
        challenge: ByteArray,
        nowMillis: Long,
    ): Boolean {
        val removed = map.remove(key) ?: return false
        if (nowMillis > removed.expiresAtMillis) return false
        return MessageDigest.isEqual(removed.challenge, challenge)
    }
}

/**
 * Atomic single-use nonce store preventing transaction signature replay.
 *
 * Implementations MUST guarantee atomic single-use semantics (e.g., Redis `SET NX PX`).
 */
public interface NonceStore {
    /** Registers a freshly issued [nonce] bound to [keyId] until [expiresAtMillis]. */
    public fun issueNonce(
        keyId: String,
        nonce: String,
        expiresAtMillis: Long,
    )

    /**
     * Atomically marks [nonce] as consumed for [keyId].
     *
     * @return `true` if [nonce] was issued, unused, and unexpired; `false` on replay or unknown nonce.
     */
    public fun consumeIfUnused(
        keyId: String,
        nonce: String,
        nowMillis: Long,
    ): Boolean
}

/** Thread-safe in-memory [NonceStore]. */
public class InMemoryNonceStore : NonceStore {
    private data class NonceRecord(
        val keyId: String,
        val expiresAtMillis: Long,
    )

    private val pending = ConcurrentHashMap<String, NonceRecord>()

    override fun issueNonce(
        keyId: String,
        nonce: String,
        expiresAtMillis: Long,
    ) {
        pending[nonce] = NonceRecord(keyId = keyId, expiresAtMillis = expiresAtMillis)
    }

    override fun consumeIfUnused(
        keyId: String,
        nonce: String,
        nowMillis: Long,
    ): Boolean {
        val record = pending.remove(nonce) ?: return false
        if (record.keyId != keyId) return false
        return nowMillis <= record.expiresAtMillis
    }
}

/**
 * Minimal Redis command abstraction so integrators can plug Jedis, Lettuce, or Spring Data Redis
 * into [RedisNonceStore] without coupling `maigbind-verifier` to a specific Redis driver.
 */
public interface RedisCommands {
    /** Executes `SET key value PX ttlMillis` (returns true on success). */
    public fun setWithTtlMillis(
        key: String,
        value: String,
        ttlMillis: Long,
    ): Boolean

    /** Atomically fetches and deletes `key` (Redis `GETDEL` or Lua `GET` + `DEL`). */
    public fun getAndDelete(key: String): String?
}

/**
 * Production-ready Redis-backed [NonceStore] using atomic `GETDEL` single-use consumption.
 */
public class RedisNonceStore(
    private val redis: RedisCommands,
    private val keyPrefix: String = "maigbind:nonce:",
) : NonceStore {
    override fun issueNonce(
        keyId: String,
        nonce: String,
        expiresAtMillis: Long,
    ) {
        val ttlMillis = (expiresAtMillis - System.currentTimeMillis()).coerceAtLeast(1_000L)
        redis.setWithTtlMillis("$keyPrefix$nonce", "$keyId:$expiresAtMillis", ttlMillis)
    }

    override fun consumeIfUnused(
        keyId: String,
        nonce: String,
        nowMillis: Long,
    ): Boolean {
        val raw = redis.getAndDelete("$keyPrefix$nonce") ?: return false
        val sep = raw.lastIndexOf(':')
        if (sep <= 0) return false
        val storedKeyId = raw.substring(0, sep)
        val expiresAt = raw.substring(sep + 1).toLongOrNull() ?: return false
        return storedKeyId == keyId && nowMillis <= expiresAt
    }
}

/** Persisted server-side representation of a device key binding. */
public data class DeviceBinding(
    val bindingId: String,
    val accountId: String,
    val keyId: String,
    val publicKeySpkiBase64Url: String,
    val status: EnrollmentStatus,
    val securityBacking: SecurityBacking,
    val isRkpChain: Boolean,
    val issuerBatchKey: String?,
    val createdAtMillis: Long,
    val activatedAtMillis: Long? = null,
    val revokedAtMillis: Long? = null,
    val pendingExpiresAtMillis: Long? = null,
)

/** Storage interface for enrolled device key bindings. */
public interface BindingStore {
    public fun save(binding: DeviceBinding)

    public fun findByBindingId(bindingId: String): DeviceBinding?

    public fun findByAccountAndKeyId(
        accountId: String,
        keyId: String,
    ): DeviceBinding?

    public fun findActiveByAccount(accountId: String): List<DeviceBinding>

    /** Marks [bindingId] as [EnrollmentStatus.REVOKED] if found and not already revoked. */
    public fun revoke(
        bindingId: String,
        revokedAtMillis: Long,
    ): Boolean

    /** Marks all non-revoked bindings for [accountId] as [EnrollmentStatus.REVOKED]. */
    public fun revokeAllForAccount(
        accountId: String,
        revokedAtMillis: Long,
    ): Int

    /**
     * Removes [EnrollmentStatus.PENDING_POP] bindings whose [DeviceBinding.pendingExpiresAtMillis]
     * is strictly before [nowMillis].
     *
     * @return the number of expired pending bindings purged.
     */
    public fun purgeExpiredPending(nowMillis: Long): Int = 0
}

/** Thread-safe in-memory [BindingStore]. */
public class InMemoryBindingStore : BindingStore {
    private val byBindingId = ConcurrentHashMap<String, DeviceBinding>()
    private val byAccountKey = ConcurrentHashMap<String, DeviceBinding>()

    override fun save(binding: DeviceBinding) {
        byBindingId[binding.bindingId] = binding
        byAccountKey["${binding.accountId}::${binding.keyId}"] = binding
    }

    override fun findByBindingId(bindingId: String): DeviceBinding? = byBindingId[bindingId]

    override fun findByAccountAndKeyId(
        accountId: String,
        keyId: String,
    ): DeviceBinding? = byAccountKey["$accountId::$keyId"]

    override fun findActiveByAccount(accountId: String): List<DeviceBinding> =
        byBindingId.values.filter { it.accountId == accountId && it.status == EnrollmentStatus.ACTIVE }

    override fun revoke(
        bindingId: String,
        revokedAtMillis: Long,
    ): Boolean {
        val current = byBindingId[bindingId] ?: return false
        if (current.status == EnrollmentStatus.REVOKED) return false
        val updated = current.copy(status = EnrollmentStatus.REVOKED, revokedAtMillis = revokedAtMillis)
        save(updated)
        return true
    }

    override fun revokeAllForAccount(
        accountId: String,
        revokedAtMillis: Long,
    ): Int {
        var count = 0
        for (binding in byBindingId.values) {
            if (binding.accountId == accountId && binding.status != EnrollmentStatus.REVOKED) {
                save(binding.copy(status = EnrollmentStatus.REVOKED, revokedAtMillis = revokedAtMillis))
                count++
            }
        }
        return count
    }

    override fun purgeExpiredPending(nowMillis: Long): Int {
        var purged = 0
        for ((bindingId, binding) in byBindingId) {
            val expiresAt = binding.pendingExpiresAtMillis
            if (binding.status == EnrollmentStatus.PENDING_POP &&
                expiresAt != null &&
                nowMillis > expiresAt
            ) {
                if (byBindingId.remove(bindingId, binding)) {
                    byAccountKey.remove("${binding.accountId}::${binding.keyId}", binding)
                    purged++
                }
            }
        }
        return purged
    }
}

/**
 * **Experimental** velocity tracker observing how many distinct accounts enroll with the same
 * leaf-adjacent batch attestation certificate within a sliding time window.
 *
 * Note: Google factory batch certificates are legitimately shared across ~100,000+ devices of a
 * product line; lifetime counting would trigger mass false positives. Only high-velocity bursts
 * inside a short time window should be surfaced as telemetry.
 */
public interface KeyboxUsageTracker {
    /**
     * Records [accountId] using [batchCertKey] at [nowMillis] and returns the distinct account count
     * observed within `[nowMillis - windowMillis, nowMillis]`.
     */
    public fun recordAndCountInWindow(
        batchCertKey: String,
        accountId: String,
        nowMillis: Long,
        windowMillis: Long,
    ): Int
}

/**
 * Thread-safe in-memory windowed [KeyboxUsageTracker].
 *
 * **Not for production use:** retains batch certificate map keys in memory indefinitely without
 * outer-map eviction. Production deployments should use a bounded or TTL-backed store (such as
 * Redis sorted sets or hashes with `EXPIRE`).
 */
public class InMemoryKeyboxUsageTracker : KeyboxUsageTracker {
    private val eventsByBatchKey = ConcurrentHashMap<String, ConcurrentHashMap<String, Long>>()

    override fun recordAndCountInWindow(
        batchCertKey: String,
        accountId: String,
        nowMillis: Long,
        windowMillis: Long,
    ): Int {
        val accountTimestamps = eventsByBatchKey.computeIfAbsent(batchCertKey) { ConcurrentHashMap() }
        accountTimestamps[accountId] = nowMillis
        val cutoff = nowMillis - windowMillis
        accountTimestamps.entries.removeIf { it.value < cutoff }
        return accountTimestamps.size
    }
}
