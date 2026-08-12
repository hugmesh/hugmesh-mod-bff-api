package net.hugmesh.modbff.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * SERVICE-LOCAL BFF SESSION AUTHENTICATION — bridges an opaque {@code bff_} session
 * token into a REAL Spring Security {@link Authentication}, so mod-bff-api's OWN
 * declarative {@code hasAnyRole("MOD","ADMIN","SUPERADMIN")} chain gate ({@code
 * SecurityConfig}) and {@code @PreAuthorize("hasAnyRole('MOD','ADMIN')")} method gates
 * ({@code ModController}) can see it.
 *
 * <h3>Why this exists</h3>
 * The gateway's own {@code BffSessionAuthFilter} (hugmesh-gateway) authenticates a
 * bff_ session AT THE GATEWAY, for the gateway's OWN route-access decision — that
 * authentication is local to the gateway's request-processing context and does not
 * cross HTTP to a downstream service. mod-bff-api's {@code oauth2ResourceServer().jwt(...)}
 * config is (correctly) inert to a non-JWT bff_ token, so — until this filter — a fully
 * registered, real ROLE_MOD native-login session 401'd at mod-bff-api's own security
 * for every {@code /bff/mod/**} action, even though mod-ui reaches this exact surface
 * with same-origin {@code fetch(..., {credentials: 'include'})} carrying the
 * {@code bff_session} cookie (see {@code mod-bff.service.ts}), and even though the
 * gateway's OWN route-access layer had already granted the request through. Confirmed
 * live 2026-07 against the local compose stack: a real seeded MOD session 401'd when
 * presented directly to mod-bff-api (bypassing the gateway), via either the
 * {@code Authorization: Bearer bff_...} header or the {@code bff_session} cookie.
 *
 * <h3>Resolution: HTTP, not a local DB call</h3>
 * Unlike admin-bff-api's own {@code net.hugmesh.authcore.config.BffCookieAuthenticationWebFilter}
 * (which resolves a session via a direct, in-process {@code AccountStore} call — that
 * service owns the accounts/bff_session tables), mod-bff-api has NO local database
 * access to those tables (network-isolated by design). This filter therefore resolves
 * a session the way the GATEWAY does: {@link AdminBffSessionIntrospectClient} calls
 * admin-bff's {@code GET /bff/internal/session/introspect} with
 * {@code Authorization: Bearer bff_<token>}, which is exactly as trustworthy as the
 * gateway's own bridge (same endpoint, same DB-backed lookup) — just performed from a
 * different service.
 *
 * <h3>Authority mapping</h3>
 * Mirrors BOTH the gateway's {@code BffSessionAuthFilter.buildAuthorities} and
 * admin-bff-api's local {@code BffCookieAuthenticationWebFilter.buildAuthorities}
 * (the three are kept in lockstep by convention): {@code ROLE_USER} floor always
 * granted; if {@code registrationComplete} is false, ONLY the floor; otherwise each
 * role maps to {@code ROLE_<UPPER>}, deduplicated against the floor;
 * {@code MFA_SATISFIED} is added when the introspect response reports it.
 *
 * <h3>Suspended/banned accounts — explicit deny, mirroring the gateway</h3>
 * admin-bff's introspect body may report {@code status: "suspended"|"banned"} on a
 * still-live session (the suspension check is live, not cached). Exactly like the
 * gateway's own filter, this is an explicit {@code 403} — the exchange is completed
 * directly and {@code chain.filter(exchange)} is NEVER called on this branch — rather
 * than silently degrading to "unauthenticated" (which would still merely 401, but
 * would blur a deliberate ban decision with an ordinary invalid/absent token). This is
 * defence-in-depth: the gateway already denies a banned session before proxying here in
 * production, but mod-bff-api's own gate should not depend on that for correctness.
 *
 * <h3>Fail-closed on introspection failure</h3>
 * Mirrors the gateway's posture exactly:
 * <ul>
 *   <li>admin-bff returns 401 (unknown/expired session, OR a misconfigured internal
 *       token — indistinguishable at this layer, same as the gateway) → pass through
 *       UNAUTHENTICATED; the downstream {@code hasAnyRole()}/{@code .authenticated()}
 *       rule then produces the 401/403 for protected paths, public paths still
 *       succeed.</li>
 *   <li>admin-bff unreachable, times out, or returns 5xx → {@code 503 Service
 *       Unavailable}. A bff_ token that cannot be validated is NEVER treated as
 *       authenticated, and is never silently dropped to anonymous either — the caller
 *       is told the session backend is down rather than getting a misleading 401/403.</li>
 * </ul>
 *
 * <h3>Non-interference with JWT auth</h3>
 * Skips entirely — no network call at all — when no {@code bff_} token is present
 * (absent header/cookie, or a header present but not {@code Bearer bff_...}, e.g. a
 * real Casdoor JWT). A real JWT request is completely untouched by this filter.
 *
 * <h3>Token extraction — header OR cookie</h3>
 * mod-bff-api has none of admin-bff-api's {@code SessionCookieWebFilter} carrier
 * normalisation (this service never had one), so — exactly like the gateway's own
 * {@code BffSessionAuthFilter.extractToken} — this filter reads BOTH carriers
 * directly, in priority order: {@code Authorization: Bearer bff_...} header first,
 * then the {@code bff_session} cookie.
 *
 * <h3>Ordering</h3>
 * {@code HIGHEST_PRECEDENCE + 10} — before Spring Security's own {@code
 * WebFilterChainProxy} resolves the JWT decoder, so a populated SecurityContext here
 * short-circuits the (inert-anyway) JWT resource-server attempt. Matches admin-bff-api's
 * local filter's order exactly (there is no {@code SessionCookieWebFilter} {@code +5}
 * stage in this service to sit behind).
 *
 * <h3>Tolerating an unwired client — {@code ObjectProvider}, not {@code @ConditionalOnBean}</h3>
 * Boot's {@code @WebFluxTest} slice auto-includes every {@code WebFilter}-typed bean
 * found by its component scan. An earlier admin-bff-api version of this idea used
 * {@code @ConditionalOnBean(AccountStore.class)} on a plain {@code @Component} to dodge
 * that — reverted because Spring's own docs call that pattern unsafe outside
 * {@code @Configuration}/auto-configuration classes (it happened to work only by
 * incidental package-scan ordering). This filter instead takes
 * {@code ObjectProvider<AdminBffSessionIntrospectClient>}, resolved lazily per-request:
 * the bean ALWAYS constructs, and an absent client (any test context that does not
 * import {@link AdminBffSessionAuthConfig}) behaves exactly like an absent {@code bff_}
 * token — pass through unauthenticated, identical to today's pre-fix behaviour there.
 *
 * <h3>Exactly-once {@code chain.filter(exchange)} — the double-invocation trap</h3>
 * {@code resolved.flatMap(auth -> chain.filter(exchange)...).switchIfEmpty(chain.filter(exchange))}
 * looks equivalent to branching on presence/absence but is NOT: {@code chain.filter()}
 * returns {@code Mono<Void>}, which NEVER emits {@code onNext} even on successful
 * completion, so {@code switchIfEmpty} would ALWAYS treat a successful auth as "empty"
 * too and invoke {@code chain.filter(exchange)} a SECOND time — double-executing the
 * downstream handler in production (duplicate side effects; the second call typically
 * fails once the response is already committed). This filter avoids the trap by first
 * resolving to a single {@code Decision} value (never a bare {@code Mono<Void>}), then
 * branching with a plain {@code switch} to EXACTLY ONE terminal action per branch: two
 * branches call {@code chain.filter(exchange)} once each (authenticate / pass-through);
 * the other two branches complete the exchange directly and never touch
 * {@code chain.filter(exchange)} at all (forbidden / backend-unavailable). See
 * {@code BffCookieAuthenticationWebFilterTest} for a call-counting regression test.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
public class BffCookieAuthenticationWebFilter implements WebFilter {

    private static final Logger log = LoggerFactory.getLogger(BffCookieAuthenticationWebFilter.class);

    /** Cookie name as defined by admin-bff's SessionCookieWebFilter / the gateway's
     *  BffSessionAuthFilter — the SAME cookie the browser presents to every service. */
    static final String SESSION_COOKIE = "bff_session";

    /** Token prefix that uniquely identifies opaque BFF session tokens. Public so
     *  {@code SecurityConfig}'s resource-server {@code bearerTokenConverter} can skip a
     *  {@code bff_} Bearer without re-declaring the prefix as a second, driftable
     *  literal (see {@code SecurityConfig#configureResourceServer}). */
    public static final String BFF_PREFIX = "bff_";

    /** Authority granted when the MFA challenge has been satisfied for this session.
     *  Matches the gateway's own BffSessionAuthFilter.MFA_SATISFIED constant. */
    public static final String MFA_SATISFIED = "MFA_SATISFIED";

    /** Response header naming the reason a request was explicitly denied by this
     *  filter (forbidden branch only) — mirrors the gateway's X-BFF-Denied. */
    private static final String DENIED_HEADER = "X-Bff-Denied";

    private final ObjectProvider<AdminBffSessionIntrospectClient> clients;
    private final long timeoutMs;

    public BffCookieAuthenticationWebFilter(
            ObjectProvider<AdminBffSessionIntrospectClient> clients,
            @Value("${app.bff-session.timeout-ms:2000}") long timeoutMs) {
        this.clients = clients;
        this.timeoutMs = timeoutMs;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        String token = extractToken(exchange);
        AdminBffSessionIntrospectClient client = token == null ? null : clients.getIfAvailable();
        if (client == null) {
            // No bff_ token, or no client wired (e.g. a slice-test context) — leave the
            // JWT path (and any anonymous/permitAll rule) completely undisturbed.
            return chain.filter(exchange);
        }

        Mono<Decision> decision = client.introspect(token)
                .timeout(Duration.ofMillis(timeoutMs))
                .map(BffCookieAuthenticationWebFilter::decide)
                .onErrorResume(WebClientResponseException.Unauthorized.class,
                        e -> Mono.just(Decision.passThrough()))
                .onErrorResume(ex -> Mono.just(failClosed(ex)));

        // See the class doc "Exactly-once chain.filter(exchange)" section: resolve to a
        // single Decision FIRST, then branch to exactly one terminal action — never a
        // flatMap+switchIfEmpty pair racing against a Mono<Void> that never emits onNext.
        return decision.flatMap(d -> apply(d, exchange, chain));
    }

    private static Mono<Void> apply(Decision d, ServerWebExchange exchange, WebFilterChain chain) {
        return switch (d.kind()) {
            case AUTHENTICATE -> chain.filter(exchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(d.authentication()));
            case PASS_THROUGH -> chain.filter(exchange);
            case FORBIDDEN -> reject(exchange, HttpStatus.FORBIDDEN, "account-" + d.reason());
            case UNAVAILABLE -> rejectServiceUnavailable(exchange);
        };
    }

    // ── decision resolution ───────────────────────────────────────────────────

    /** Package-private (not private) so a unit test can assert on decision outcomes
     *  directly, without driving the full reactive filter. */
    enum Kind { AUTHENTICATE, PASS_THROUGH, FORBIDDEN, UNAVAILABLE }

    /** The single resolved outcome of a bff_ token lookup, branched on exactly once.
     *  Package-private for the same reason as {@link Kind}. */
    record Decision(Kind kind, Authentication authentication, String reason) {
        static Decision authenticate(Authentication a) { return new Decision(Kind.AUTHENTICATE, a, null); }
        static Decision passThrough() { return new Decision(Kind.PASS_THROUGH, null, null); }
        static Decision forbidden(String reason) { return new Decision(Kind.FORBIDDEN, null, reason); }
        static Decision unavailable() { return new Decision(Kind.UNAVAILABLE, null, null); }
    }

    /** Package-private (not private) so a unit test can exercise the mapping directly. */
    static Decision decide(BffSessionIntrospection intro) {
        String status = intro.status();
        if ("suspended".equalsIgnoreCase(status) || "banned".equalsIgnoreCase(status)) {
            log.warn("[bff-cookie-auth] denied — account status={} id={}", status, intro.id());
            return Decision.forbidden(status.toLowerCase(Locale.ROOT));
        }
        return Decision.authenticate(authenticationFor(intro));
    }

    private static Decision failClosed(Throwable ex) {
        log.error("[bff-cookie-auth] admin-bff session introspection failed for a bff_ token — "
                + "failing closed (503): {}", ex.toString());
        return Decision.unavailable();
    }

    // ── token extraction ──────────────────────────────────────────────────────

    /**
     * Extracts a {@code bff_} token from the exchange: {@code Authorization: Bearer}
     * header first, then the {@code bff_session} cookie — mirrors the gateway's own
     * {@code BffSessionAuthFilter.extractToken} exactly, since mod-bff-api has no
     * upstream carrier-normalisation filter of its own.
     */
    static String extractToken(ServerWebExchange exchange) {
        String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null) {
            String trimmed = authHeader.trim();
            if (trimmed.regionMatches(true, 0, "Bearer ", 0, 7)) {
                String candidate = trimmed.substring(7).trim();
                if (candidate.startsWith(BFF_PREFIX)) {
                    return candidate;
                }
                // Present but not a bff_ token (e.g. a Casdoor JWT) — skip immediately.
                return null;
            }
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

    // ── authority mapping ─────────────────────────────────────────────────────

    private static Authentication authenticationFor(BffSessionIntrospection intro) {
        return new UsernamePasswordAuthenticationToken(intro.id(), null, buildAuthorities(intro));
    }

    /** Package-private (not private) so a unit test can exercise the mapping directly. */
    static List<GrantedAuthority> buildAuthorities(BffSessionIntrospection intro) {
        var authorities = new ArrayList<GrantedAuthority>();
        authorities.add(new SimpleGrantedAuthority("ROLE_USER"));

        if (!intro.registrationComplete()) {
            return authorities;
        }

        if (intro.roles() != null) {
            for (String role : intro.roles()) {
                if (role != null && !role.isBlank()) {
                    String authority = "ROLE_" + role.trim().toUpperCase(Locale.ROOT);
                    if (!"ROLE_USER".equals(authority)) {
                        authorities.add(new SimpleGrantedAuthority(authority));
                    }
                }
            }
        }

        if (intro.mfaSatisfied()) {
            authorities.add(new SimpleGrantedAuthority(MFA_SATISFIED));
        }

        return authorities;
    }

    // ── response helpers ──────────────────────────────────────────────────────

    private static Mono<Void> reject(ServerWebExchange exchange, HttpStatus status, String reason) {
        exchange.getResponse().setStatusCode(status);
        exchange.getResponse().getHeaders().add(DENIED_HEADER, reason);
        return exchange.getResponse().setComplete();
    }

    private static Mono<Void> rejectServiceUnavailable(ServerWebExchange exchange) {
        exchange.getResponse().setStatusCode(HttpStatus.SERVICE_UNAVAILABLE);
        exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] body = "{\"error\":\"session_backend_unavailable\"}".getBytes(StandardCharsets.UTF_8);
        var buffer = exchange.getResponse().bufferFactory().wrap(body);
        return exchange.getResponse().writeWith(Mono.just(buffer));
    }
}
