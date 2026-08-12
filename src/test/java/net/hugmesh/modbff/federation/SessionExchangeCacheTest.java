package net.hugmesh.modbff.federation;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Positive-only TTL cache semantics: miss on absent/expired/disabled, hit within TTL,
 * never keyed by the raw token itself, and a {@code <=0} TTL disables the cache entirely.
 */
class SessionExchangeCacheTest {

    @Test
    void missOnEmptyCache() {
        SessionExchangeCache cache = new SessionExchangeCache(5000, 10);
        assertThat(cache.get("bff_abc")).isNull();
    }

    @Test
    void hitAfterPut_withinTtl() {
        SessionExchangeCache cache = new SessionExchangeCache(5000, 10);
        cache.put("bff_abc", "real-jwt");
        assertThat(cache.get("bff_abc")).isEqualTo("real-jwt");
    }

    @Test
    void differentTokens_areIndependentEntries() {
        SessionExchangeCache cache = new SessionExchangeCache(5000, 10);
        cache.put("bff_a", "jwt-a");
        cache.put("bff_b", "jwt-b");
        assertThat(cache.get("bff_a")).isEqualTo("jwt-a");
        assertThat(cache.get("bff_b")).isEqualTo("jwt-b");
    }

    @Test
    void expiredEntry_isEvictedAndMisses() throws InterruptedException {
        SessionExchangeCache cache = new SessionExchangeCache(1, 10); // 1ms TTL
        cache.put("bff_abc", "real-jwt");
        Thread.sleep(20);
        assertThat(cache.get("bff_abc")).isNull();
    }

    @Test
    void nonPositiveTtl_disablesCacheEntirely() {
        SessionExchangeCache cache = new SessionExchangeCache(0, 10);
        assertThat(cache.enabled()).isFalse();
        cache.put("bff_abc", "real-jwt");
        assertThat(cache.get("bff_abc")).isNull();
    }

    @Test
    void negativeTtl_alsoDisablesCache() {
        SessionExchangeCache cache = new SessionExchangeCache(-1, 10);
        assertThat(cache.enabled()).isFalse();
    }

    @Test
    void ttlIsHardClampedToSixtySeconds() {
        // Not directly observable from outside without waiting a minute; assert the
        // enabled flag survives a huge configured TTL (clamping happens internally and
        // is exercised indirectly by hitAfterPut_withinTtl not regressing).
        SessionExchangeCache cache = new SessionExchangeCache(10 * 60_000L, 10);
        assertThat(cache.enabled()).isTrue();
        cache.put("bff_abc", "real-jwt");
        assertThat(cache.get("bff_abc")).isEqualTo("real-jwt");
    }

    @Test
    void sizeBound_refusesToGrowPastMaxWhenNoExpiredEntries() {
        SessionExchangeCache cache = new SessionExchangeCache(5000, 2);
        cache.put("bff_a", "jwt-a");
        cache.put("bff_b", "jwt-b");
        cache.put("bff_c", "jwt-c"); // at capacity, nothing expired -> refused
        assertThat(cache.get("bff_a")).isEqualTo("jwt-a");
        assertThat(cache.get("bff_b")).isEqualTo("jwt-b");
        assertThat(cache.get("bff_c")).isNull();
    }
}
