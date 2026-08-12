package net.hugmesh.modbff.federation;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Captures the raw, still-opaque {@code bff_} session bearer (the {@code Authorization}
 * header, or the {@code bff_session} cookie) into the Reactor {@code Context} — under
 * {@link #CONTEXT_KEY} — so {@link BearerForwardingFilter} can read it from INSIDE a
 * downstream {@code WebClient} {@link org.springframework.web.reactive.function.client.ExchangeFilterFunction},
 * where the original {@link ServerWebExchange} (and therefore the raw request header) is
 * not otherwise reachable.
 *
 * <h3>Why this exists</h3>
 * {@link BffCookieAuthenticationWebFilter} resolves a {@code bff_} token into a validated
 * {@link org.springframework.security.authentication.UsernamePasswordAuthenticationToken}
 * with {@code credentials == null} — unlike {@link org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken},
 * which carries the raw JWT as its {@code getToken()} credential, the native-login
 * {@code Authentication} carries NO raw credential {@link BearerForwardingFilter} could
 * otherwise read off the reactive {@code SecurityContext} to attempt a custody exchange
 * (see {@code SessionExchangeService}). Rather than threading the raw token through {@code
 * Authentication} — which would require changing {@code BffCookieAuthenticationWebFilter}'s
 * construction site, and for admin-bff-api that class lives in the SHARED {@code
 * hugmesh-auth-core} library, so doing so would force a cross-repo auth-core release
 * admin-bff-api would then depend on before this fix could even build — this filter
 * independently captures the SAME raw token straight off the request, the same way {@code
 * BffCookieAuthenticationWebFilter} itself does, into the Reactor {@code Context} that
 * {@code ExchangeFilterFunction}s already read from for {@link BearerForwardingFilter}'s
 * existing JWT-forwarding path (proof this propagation works: {@link
 * ReactiveSecurityContextHolder}-based JWT forwarding already relies on the identical
 * mechanism today).
 *
 * <h3>What this does NOT do</h3>
 * This filter performs NO session lookup, NO validation, and grants NO authority — it is
 * a pure, side-effect-free header/cookie read, the same risk profile as any WebFilter that
 * reads a request header (e.g. {@link SessionCookieWebFilter}-equivalent normalisation).
 * The captured value is only ever CONSUMED by {@code SessionExchangeService#exchange},
 * which re-validates it from scratch against admin-bff's own fail-closed {@code
 * POST /bff/internal/session/exchange} (suspension gate, custody decrypt, etc. — see that
 * endpoint's own javadoc on {@code InternalAccountController}). A garbage, expired, or
 * forged candidate captured here simply fails THAT downstream validation (404/401) and
 * {@link BearerForwardingFilter} falls through to no header — exactly as if this filter
 * had never run.
 *
 * <h3>Unconditionally registered — not gated behind {@code app.bff-exchange.enabled}</h3>
 * Unlike {@code SessionExchangeConfig} (the client/cache that actually costs a network
 * call), this filter is always active: it is an in-memory header/cookie read with no I/O,
 * so gating it would only add a second flag-check for zero benefit. When the exchange
 * feature is off (the default), the captured value is simply never consumed.
 *
 * <h3>Ordering</h3>
 * Runs early ({@code HIGHEST_PRECEDENCE + 9}, immediately before {@link
 * BffCookieAuthenticationWebFilter}'s {@code +10}) — though the exact position relative to
 * that filter does not matter: this filter reads the raw request directly (header OR
 * cookie, mirroring {@code BffCookieAuthenticationWebFilter#extractToken} exactly) rather
 * than depending on anything the other filter resolves.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 9)
public class BffRawTokenContextWebFilter implements WebFilter {

    /** Reactor Context key the captured raw token is stored under. Package-visible so
     *  {@link BearerForwardingFilter} (same package) can read it without a second
     *  driftable literal. */
    static final String CONTEXT_KEY = "net.hugmesh.modbff.federation.rawBffToken";

    private static final String BFF_PREFIX = "bff_";
    private static final String SESSION_COOKIE = "bff_session";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String token = extractToken(exchange);
        if (token == null) {
            return chain.filter(exchange);
        }
        return chain.filter(exchange).contextWrite(ctx -> ctx.put(CONTEXT_KEY, token));
    }

    /**
     * {@code Authorization: Bearer bff_...} header first, then the {@code bff_session}
     * cookie — mirrors {@code BffCookieAuthenticationWebFilter#extractToken} exactly (this
     * service has no upstream carrier-normalisation filter of its own). Package-private
     * (not private) so a unit test can exercise the extraction directly.
     */
    static String extractToken(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null) {
            String trimmed = authHeader.trim();
            if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
                String candidate = trimmed.substring(7).trim();
                return candidate.startsWith(BFF_PREFIX) ? candidate : null;
            }
            // Present but not a bff_ Bearer (e.g. a Casdoor JWT) — not our concern.
            return null;
        }

        var cookies = exchange.getRequest().getCookies().get(SESSION_COOKIE);
        if (cookies != null && !cookies.isEmpty()) {
            String value = cookies.get(0).getValue();
            if (value != null && !value.isBlank()) {
                return value;
            }
        }

        return null;
    }
}
