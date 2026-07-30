package systems.hugmesh.modbff.federation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Positive-only TTL cache for a resolved custody JWT, keyed by {@code sha256(raw bff_
 * token)} — the raw token itself is NEVER used as a cache key or logged. Mirrors {@code
 * systems.hugmesh.gateway.filter.BffJwtExchangeWebFilter}'s own cache EXACTLY (same
 * shape, same defaults, same rationale) — see {@link SessionExchangeService}'s class
 * javadoc for the "TTL is the suspension-bypass window" reasoning this cache exists to
 * bound.
 *
 * <p>A {@link ConcurrentHashMap} (no new cache dependency on this classpath), manual TTL
 * plus a crude size-bound eviction. NEGATIVE/failed exchanges are NEVER represented here
 * — {@link SessionExchangeService} only ever calls {@link #put} on a successful exchange,
 * so a transient admin-bff blip can never pin a session to "no bearer" for the TTL, and an
 * attacker cannot poison the cache by forcing a failure.
 */
final class SessionExchangeCache {

    private final long ttlMillis;
    private final int maxSize;
    private final boolean enabled;
    private final ConcurrentHashMap<String, Entry> cache = new ConcurrentHashMap<>();

    /**
     * @param ttlMillisConfigured {@code <= 0} disables the cache ENTIRELY (every call
     *                            re-consults the exchange endpoint — zero suspension-bypass
     *                            window); otherwise hard-clamped to a 60s ceiling so a
     *                            misconfiguration can never cache a swap longer than a
     *                            minute (matches the gateway's own clamp).
     * @param maxSizeConfigured   crude size bound; clamped to at least 1.
     */
    SessionExchangeCache(long ttlMillisConfigured, int maxSizeConfigured) {
        this.enabled = ttlMillisConfigured > 0;
        this.ttlMillis = this.enabled ? Math.min(ttlMillisConfigured, 60_000L) : 0L;
        this.maxSize = Math.max(maxSizeConfigured, 1);
    }

    boolean enabled() {
        return enabled;
    }

    /** {@code null} on a miss (absent, expired, or the cache is disabled). */
    String get(String rawToken) {
        if (!enabled) {
            return null;
        }
        String key = hash(rawToken);
        Entry entry = cache.get(key);
        if (entry == null) {
            return null;
        }
        if (entry.isExpired()) {
            // Lazy eviction: a TTL-elapsed entry forces a fresh exchange, so a revoked/
            // suspended session stops authorising within one TTL of the swap.
            cache.remove(key, entry);
            return null;
        }
        return entry.jwt();
    }

    /** Record a SUCCESSFUL exchange only — never call this for a failure. */
    void put(String rawToken, String jwt) {
        if (!enabled) {
            return;
        }
        String key = hash(rawToken);
        if (cache.size() >= maxSize) {
            cache.entrySet().removeIf(e -> e.getValue().isExpired());
            if (cache.size() >= maxSize) {
                return;
            }
        }
        cache.put(key, new Entry(jwt, System.currentTimeMillis() + ttlMillis));
    }

    private record Entry(String jwt, long expiresAtMillis) {
        boolean isExpired() {
            return System.currentTimeMillis() >= expiresAtMillis;
        }
    }

    /** SHA-256 of the raw token, lower-case hex. */
    private static String hash(String value) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is mandated by the JLS-required provider set; unreachable.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
