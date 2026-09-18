package net.hugmesh.modbff.federation;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Operator decision 60 (2026-09-18, hugmesh-mod-bff-api#15, "extend" — the exact shape of
 * hugmesh-gateway PR #30's decision 7): the mirrored {@code app.bff-exchange.cache-ttl-ms}
 * default must be {@code 0} (cache OFF) in THREE places that have to agree —
 * {@link SessionExchangeCache#DEFAULT_CACHE_TTL_MS} (the pin), the {@code @Value} fallback
 * on {@link SessionExchangeConfig#sessionExchangeCache}, and {@code application.yml} — and
 * that agreement must hold BEHAVIOURALLY, not just as three matching literals.
 */
class SessionExchangeCacheTtlDefaultTest {

    // ── (a) the named constant is the pin ───────────────────────────────
    @Test
    void namedConstant_is0() {
        assertThat(SessionExchangeCache.DEFAULT_CACHE_TTL_MS).isZero();
    }

    // ── (b) the @Value fallback on the bean method agrees with the constant ──
    @Test
    void configValueFallback_matchesTheNamedConstant() throws NoSuchMethodException {
        Method beanMethod = SessionExchangeConfig.class.getDeclaredMethod(
                "sessionExchangeCache", long.class, int.class);
        Parameter ttlParam = beanMethod.getParameters()[0];
        Value value = ttlParam.getAnnotation(Value.class);
        assertThat(value)
                .as("sessionExchangeCache(long cacheTtlMillis, ...) must carry an @Value default")
                .isNotNull();
        String spel = value.value(); // "${app.bff-exchange.cache-ttl-ms:0}"
        assertThat(spel).startsWith("${app.bff-exchange.cache-ttl-ms:").endsWith("}");
        String fallback = spel.substring(spel.indexOf(':') + 1, spel.length() - 1);
        assertThat(fallback)
                .as("the @Value fallback must stay at 0 (cache OFF — operator decision 60, "
                        + "2026-09-18): 5000 reopens a 5 s suspension-bypass window with no YAML "
                        + "change to review")
                .isEqualTo("0")
                .isEqualTo(String.valueOf(SessionExchangeCache.DEFAULT_CACHE_TTL_MS));
    }

    // ── (c) the wired application.yml default agrees with the constant ──
    @Test
    void applicationYml_cacheTtlDefault_is0_cacheOff_notThe5000Window() throws IOException {
        // The constructor/@Value ":0" fallback is DEAD while application.yml supplies the
        // key, so the OPERATIVE default is whatever the YAML pins — this is the guard that
        // actually matters at runtime.
        var sources = new org.springframework.boot.env.YamlPropertySourceLoader()
                .load("application.yml", new ClassPathResource("application.yml"));
        String raw = sources.stream()
                .map(ps -> ps.getProperty("app.bff-exchange.cache-ttl-ms"))
                .filter(Objects::nonNull).map(String::valueOf)
                .findFirst().orElse(null);
        assertThat(raw)
                .as("application.yml must wire app.bff-exchange.cache-ttl-ms as an env placeholder")
                .isNotNull()
                .startsWith("${APP_BFF_EXCHANGE_CACHE_TTL_MS:")
                .endsWith("}");
        String yamlDefault = raw.substring(raw.indexOf(':') + 1, raw.length() - 1);
        assertThat(yamlDefault)
                .as("application.yml must default app.bff-exchange.cache-ttl-ms to 0 (cache OFF) — "
                        + "5000 reopens a 5 s suspension-bypass window")
                .isEqualTo("0")
                .isEqualTo(String.valueOf(SessionExchangeCache.DEFAULT_CACHE_TTL_MS));
    }

    // ── (d) BEHAVIOURAL: the shipped default, wired end to end, round-trips every call ──
    @Test
    void shippedDefault_cacheOff_everyExchangeRoundTripsToAdminBff_aDriftBackTo5000GoesRed() {
        // Build the cache from the REAL constant (the same value the @Value fallback and the
        // YAML default are independently pinned to above), wire it into a real
        // SessionExchangeService, and prove THREE exchanges for the SAME bff_ token are THREE
        // transport calls — not one. If any of the three pinned locations drifted back to
        // 5000, this loop would collapse to a single transport call and the final assertion
        // goes red; the three static guards above catch the number, this one catches the
        // MECHANISM (a cache that reports "disabled" but still serves a second call would
        // slip past a check that only reads the configured number).
        AtomicInteger calls = new AtomicInteger();
        SessionExchangeCache cache = new SessionExchangeCache(SessionExchangeCache.DEFAULT_CACHE_TTL_MS, 10_000);
        assertThat(cache.enabled()).as("the shipped default disables the cache").isFalse();

        SessionExchangeService service = new SessionExchangeService(
                rawToken -> {
                    calls.incrementAndGet();
                    return Mono.just("custody-" + calls.get());
                },
                cache, Duration.ofSeconds(1));

        List<String> results = new java.util.ArrayList<>();
        for (int i = 1; i <= 3; i++) {
            StepVerifier.create(service.exchange("bff_shipped-default"))
                    .assertNext(results::add)
                    .verifyComplete();
        }
        assertThat(results)
                .as("each request forwards the swap minted for IT, never a cached one")
                .containsExactly("custody-1", "custody-2", "custody-3");
        assertThat(calls.get())
                .as("cache OFF by default => admin-bff's exchange gate is consulted on EVERY "
                        + "call (3 requests, 3 swaps); a 5000 default would make this 1")
                .isEqualTo(3);
    }
}
