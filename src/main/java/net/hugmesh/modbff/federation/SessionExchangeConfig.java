package net.hugmesh.modbff.federation;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;

/**
 * Wires the native-login ({@code bff_}) → custody-JWT exchange path {@link
 * BearerForwardingFilter} uses for a native-login caller (a {@code
 * UsernamePasswordAuthenticationToken}, resolved by {@code BffCookieAuthenticationWebFilter}
 * — never a Casdoor JWT).
 *
 * <h3>GATED OFF BY DEFAULT</h3>
 * {@code app.bff-exchange.enabled=false} (default) ⇒ this whole config is absent ⇒ {@link
 * BearerForwardingFilter} degrades to EXACTLY today's behaviour for a native-login caller
 * (no {@code Authorization} header forwarded) with ZERO extra network calls — {@code
 * SessionExchangeClient}/{@code SessionExchangeCache}/{@link SessionExchangeService} simply
 * do not exist as beans, and {@link BearerForwardingFilter} resolves {@code
 * ObjectProvider<SessionExchangeService>.getIfAvailable()} to {@code null} every time.
 *
 * <p>This flag is DELIBERATELY separate from (and must be turned on IN ADDITION to)
 * admin-bff-api's {@code app.bff.custody-key} (and, for the lazy-refresh leg, {@code
 * app.bff.oidc.enabled}) — those gate whether admin-bff-api's OWN {@code
 * /bff/internal/session/exchange} endpoint can serve a real Bearer at all; THIS flag gates
 * whether mod-bff-api even ATTEMPTS to call it. Turning this flag on alone (without
 * custody configured on admin-bff-api) is harmless but pointless: every exchange attempt
 * receives a 503 ("custody disabled") and {@link BearerForwardingFilter} still falls
 * through to no header — just after one extra in-cluster round trip. Mirrors the SAME
 * two-layer opt-in the gateway's own {@code hugmesh.gateway.bff-exchange.enabled} +
 * admin-bff's custody flags already require.
 *
 * <h3>Reuses the EXISTING admin-bff internal WebClient — no new credential</h3>
 * {@code adminBffInternalWebClient} ({@code
 * net.hugmesh.modbff.auth.AdminBffSessionAuthConfig}) already talks to admin-bff's
 * {@code /bff/internal/**} surface — same base URL ({@code admin-bff.base-url}), same
 * optional mTLS client presentation, same {@code X-Internal-Token} stamping ({@code
 * app.bff-session.internal-token}/{@code -header}). {@code /session/exchange} lives behind
 * the IDENTICAL {@code InternalTokenWebFilter} guard as {@code /session/introspect}
 * (already called on that same WebClient by {@code AdminBffSessionIntrospectClient}), so
 * this needs no new wiring beyond a second thin client on top of the same bean.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "app.bff-exchange.enabled", havingValue = "true")
public class SessionExchangeConfig {

    @Bean
    SessionExchangeClient sessionExchangeClient(WebClient adminBffInternalWebClient) {
        return new SessionExchangeClient(adminBffInternalWebClient);
    }

    @Bean
    SessionExchangeCache sessionExchangeCache(
            @Value("${app.bff-exchange.cache-ttl-ms:5000}") long cacheTtlMillis,
            @Value("${app.bff-exchange.cache-max-size:10000}") int cacheMaxSize) {
        return new SessionExchangeCache(cacheTtlMillis, cacheMaxSize);
    }

    @Bean
    SessionExchangeService sessionExchangeService(
            SessionExchangeClient sessionExchangeClient,
            SessionExchangeCache sessionExchangeCache,
            @Value("${app.bff-exchange.request-timeout-ms:3000}") long requestTimeoutMillis) {
        return new SessionExchangeService(
                sessionExchangeClient, sessionExchangeCache, Duration.ofMillis(requestTimeoutMillis));
    }
}
