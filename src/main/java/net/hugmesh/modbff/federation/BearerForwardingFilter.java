package net.hugmesh.modbff.federation;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import reactor.core.publisher.Mono;

/**
 * Token-injecting {@link ExchangeFilterFunction} for the reactive WebClients this
 * BFF uses as a downstream client. It reads the CALLER's Authentication off the
 * reactive {@code SecurityContext} (set by the resource-server filter chain, or by
 * {@code BffCookieAuthenticationWebFilter} for a native-login caller) and forwards a
 * bearer as {@code Authorization: Bearer <token>} on every outgoing request, so
 * federation-api (and any other Casdoor-gated downstream) authorises the request as
 * the original moderator — NOT as a service identity. This is what lets
 * federation-api's own {@code @PreAuthorize('hasAnyRole MOD, ADMIN')} + manifest
 * visibility-filter see the real principal.
 *
 * <h3>Two callers, two bearer sources</h3>
 * <ul>
 *   <li><b>A real Casdoor JWT caller</b> ({@link JwtAuthenticationToken}) — the token is
 *       forwarded VERBATIM, unchanged from the original behaviour of this filter.</li>
 *   <li><b>A native-login ({@code bff_} session) caller</b> ({@link
 *       UsernamePasswordAuthenticationToken}, resolved by {@code
 *       BffCookieAuthenticationWebFilter}) — this Authentication carries NO raw JWT
 *       (unlike {@code JwtAuthenticationToken}, its {@code credentials} is {@code null}).
 *       Without a real bearer to forward, EVERY prior version of this filter sent the
 *       downstream request with NO {@code Authorization} header at all — silently
 *       breaking a native-login admin/mod's ability to reach a JWT-only-gated downstream
 *       (federation-api's {@code /api/federation/moderation/**}, in particular), even
 *       though the SAME caller had already passed this BFF's own local
 *       {@code hasAnyRole()} gate. This filter now ATTEMPTS a best-effort custody
 *       exchange via {@link SessionExchangeService} (native-login → real Casdoor JWT,
 *       reading the raw {@code bff_} token {@link BffRawTokenContextWebFilter} captured
 *       into the Reactor {@code Context} for this exact purpose) and forwards the
 *       resulting Bearer on success.</li>
 * </ul>
 *
 * <p><b>Fail-open, by design, on the native-login path.</b> {@link
 * SessionExchangeService#exchange} NEVER errors — every failure (the feature not being
 * opted in via {@code app.bff-exchange.enabled}, admin-bff-api's custody subsystem being
 * unconfigured, an unknown/expired session, a suspended/banned account, or a transient
 * outage) collapses to {@link Mono#empty()}, and this filter then falls through to
 * EXACTLY the pre-fix behaviour: no {@code Authorization} header, request forwarded
 * unmodified. See {@link SessionExchangeService}'s class javadoc for the full reasoning
 * (in particular why this is a deliberate, safe departure from the gateway's own
 * hard-fail-closed posture for the analogous swap).
 *
 * <p>If there is no Authentication on the context at all (e.g. an internal call outside
 * a request), or the Authentication is neither of the above, the request goes through
 * unmodified — the downstream then applies its own anonymous rules.
 */
public final class BearerForwardingFilter {

    private BearerForwardingFilter() {}

    /**
     * A filter that forwards the caller's bearer to the downstream — verbatim for a real
     * Casdoor JWT caller, or via a best-effort custody exchange for a native-login
     * caller. {@code exchangeServiceProvider} resolves to an ABSENT {@link
     * SessionExchangeService} whenever {@code app.bff-exchange.enabled} is unset
     * (the default) or the wiring config is not imported (e.g. a slice test) — in either
     * case the native-login branch degrades to no header, identical to today.
     */
    public static ExchangeFilterFunction forwardCallerToken(
            ObjectProvider<SessionExchangeService> exchangeServiceProvider) {
        return (request, next) -> ReactiveSecurityContextHolder.getContext()
                .map(ctx -> ctx.getAuthentication())
                .flatMap(auth -> resolveBearer(auth, exchangeServiceProvider))
                .map(token -> ClientRequest.from(request)
                        .headers(h -> h.set(HttpHeaders.AUTHORIZATION, "Bearer " + token))
                        .build())
                .defaultIfEmpty(request)
                .flatMap(next::exchange);
    }

    /** Resolve the bearer to forward for the CURRENT caller, or complete empty (no
     *  header forwarded) — never errors. */
    private static Mono<String> resolveBearer(
            Authentication auth, ObjectProvider<SessionExchangeService> exchangeServiceProvider) {
        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            return Mono.just(jwtAuth.getToken().getTokenValue());
        }
        if (auth instanceof UsernamePasswordAuthenticationToken) {
            SessionExchangeService exchangeService = exchangeServiceProvider.getIfAvailable();
            if (exchangeService == null) {
                return Mono.empty();
            }
            return Mono.deferContextual(view -> {
                String rawToken = view.getOrDefault(BffRawTokenContextWebFilter.CONTEXT_KEY, null);
                return rawToken == null ? Mono.empty() : exchangeService.exchange(rawToken);
            });
        }
        return Mono.empty();
    }
}
