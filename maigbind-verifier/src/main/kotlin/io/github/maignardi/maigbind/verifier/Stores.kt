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
}

/**
 * Heuristic tracker detecting when the same intermediate/batch attestation certificate is shared
 * across suspiciously many distinct accounts (a strong indicator of a leaked OEM factory keybox).
 */
public interface KeyboxUsageTracker {
    /** Records [accountId] using [batchCertKey] and returns the distinct account count observed. */
    public fun recordAndCountDistinctAccounts(
        batchCertKey: String,
        accountId: String,
    ): Int
}

/** Thread-safe in-memory [KeyboxUsageTracker]. */
public class InMemoryKeyboxUsageTracker : KeyboxUsageTracker {
    private val accountsByBatchKey = ConcurrentHashMap<String, MutableSet<String>>()

    override fun recordAndCountDistinctAccounts(
        batchCertKey: String,
        accountId: String,
    ): Int {
        val set = accountsByBatchKey.computeIfAbsent(batchCertKey) { ConcurrentHashMap.newKeySet() }
        set.add(accountId)
        return set.size
    }
}
