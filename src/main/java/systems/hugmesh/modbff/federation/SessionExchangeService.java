package systems.hugmesh.modbff.federation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Set;

/**
 * Best-effort native-login ({@code bff_}) → real-Casdoor-JWT custody exchange for {@link
 * BearerForwardingFilter}. This is the ONLY entry point {@link BearerForwardingFilter}
 * uses for a native-login caller — it NEVER errors: every failure mode, including the
 * routine, expected "custody disabled" 503 every default (opted-out) deployment sees,
 * collapses to {@link Mono#empty()}, which {@link BearerForwardingFilter} treats
 * identically to "no bearer available": the downstream request is forwarded with NO
 * {@code Authorization} header — exactly today's pre-fix behaviour for a native-login
 * caller.
 *
 * <h3>Why soft-degrade on EVERY failure — a deliberate departure from the gateway's own
 * {@code BffJwtExchangeWebFilter}, which hard-fails (401) on any exchange failure</h3>
 * The gateway is the SOLE authentication decision point for the many heterogeneous
 * downstream routes it proxies — it has no independent second gate to fall back on, so
 * forwarding a request it could not exchange would be a genuine authentication bypass
 * (the raw, unvalidatable {@code bff_} would reach a JWT-only resource server that has no
 * other way to reject it). {@link BearerForwardingFilter}'s situation is different: EVERY
 * downstream it forwards to (federation-api, admin-bff-api's own public surface,
 * owncast-bff-api) already has its OWN independent, already-shipped, fail-closed JWT/role
 * gate for a headerless request. Forwarding without a bearer here does not bypass
 * anything — the downstream's own resource-server config rejects it exactly as it does
 * today (401/403), with or without this feature. A hard failure at THIS layer would
 * therefore invent a brand-new outage mode (breaking federation-api calls that don't even
 * require auth, or turning a transient admin-bff blip into a hard failure of every
 * native-login moderation action) without adding any new safety property — which is why
 * every failure, transient (5xx/timeout/connection-refused) and permanent (503
 * custody-disabled/404 unknown-session/401 no-custody/403 suspended) alike, degrades the
 * SAME way. This mirrors this exact codebase's own {@code BffCookieAuthenticationWebFilter}
 * reasoning for why ITS unreachable-admin-bff case IS a hard 503: that filter resolves
 * PRIMARY authentication (the only signal for the whole request) — this service is
 * upgrading an ALREADY-established, already-vetted identity to a second credential FORMAT
 * for a defence-in-depth downstream re-check, not deciding whether the request is
 * authenticated at all.
 *
 * <h3>Operator visibility despite the uniform fail-open contract</h3>
 * Because failures never surface as an HTTP-visible symptom at this layer, an UNEXPECTED
 * failure (anything other than the exchange endpoint's own documented 503/404/401/403
 * fail-closed matrix — a stray 5xx, a timeout, connection-refused) is logged at WARN,
 * distinctly from the ROUTINE "custody disabled" 503 every opted-out deployment will see
 * constantly (logged at DEBUG). This lets an operator who HAS opted in ({@code
 * app.bff-exchange.enabled=true} + custody configured on admin-bff-api) tell "the feature
 * just isn't enabled elsewhere" apart from "the feature is enabled but broken" — without
 * changing the fail-open HTTP behaviour itself.
 *
 * <h3>Caching — mirrors the gateway's {@code BffJwtExchangeWebFilter} exactly</h3>
 * See {@link SessionExchangeCache}. Positive-only, {@code sha256(token)}-keyed, default 5s
 * hard-clamped to a 60s ceiling; {@code cache-ttl-ms<=0} disables the cache entirely (every
 * call re-consults admin-bff's exchange gate — zero suspension-bypass window). <b>The TTL
 * IS the suspension-bypass window</b>: a cache hit skips admin-bff's own {@code
 * suspensionGate()} re-check, so the TTL bounds how stale a just-banned account's
 * continued federation-api/admin-bff/owncast-bff access can be via this path — the SAME
 * reasoning the gateway's cache already worked through, reproduced here rather than
 * re-derived.
 *
 * <p><b>Public visibility.</b> {@link BearerForwardingFilter} is shared onto THREE
 * downstream {@code WebClient}s wired from three different packages ({@code
 * systems.hugmesh.modbff.admin.AdminApiConfig}, {@code .federation.FederationApiConfig},
 * {@code .owncast.OwncastApiConfig}), each declaring its own {@code
 * ObjectProvider<SessionExchangeService>} constructor/method parameter — so this type must
 * be reachable from those packages. Only the TYPE is exposed; the constructor stays
 * package-private (only {@link SessionExchangeConfig}, same package, ever calls it).
 */
public final class SessionExchangeService {

    private static final Logger log = LoggerFactory.getLogger(SessionExchangeService.class);

    /** HTTP statuses the exchange endpoint documents as its OWN fail-closed matrix —
     *  routine and expected on every deployment that hasn't (fully) opted in. Anything
     *  else is unexpected and gets a louder log. */
    private static final Set<Integer> ROUTINE_STATUSES = Set.of(503, 404, 401, 403);

    private final SessionExchangeTransport client;
    private final SessionExchangeCache cache;
    private final Duration requestTimeout;

    SessionExchangeService(SessionExchangeTransport client, SessionExchangeCache cache, Duration requestTimeout) {
        this.client = client;
        this.cache = cache;
        this.requestTimeout = requestTimeout;
    }

    /**
     * Resolve a real bearer for a raw {@code bff_} token, or complete empty. NEVER
     * propagates an error — see class javadoc.
     */
    public Mono<String> exchange(String rawToken) {
        if (rawToken == null || rawToken.isBlank()) {
            return Mono.empty();
        }
        String cached = cache.get(rawToken);
        if (cached != null) {
            return Mono.just(cached);
        }
        return client.exchange(rawToken)
                .timeout(requestTimeout)
                .doOnNext(jwt -> cache.put(rawToken, jwt))
                .onErrorResume(SessionExchangeService::isRoutineFailure, ex -> degrade(ex, true))
                .onErrorResume(ex -> degrade(ex, false));
    }

    private static boolean isRoutineFailure(Throwable ex) {
        return ex instanceof WebClientResponseException wcre
                && ROUTINE_STATUSES.contains(wcre.getStatusCode().value());
    }

    private static Mono<String> degrade(Throwable ex, boolean routine) {
        if (routine) {
            log.debug("[bff-exchange] session exchange declined ({}) — forwarding without a bearer", ex.toString());
        } else {
            log.warn("[bff-exchange] session exchange call failed UNEXPECTEDLY (custody subsystem may be "
                    + "misconfigured or unreachable — this is not the routine \"custody disabled\" case) — "
                    + "forwarding without a bearer: {}", ex.toString());
        }
        return Mono.empty();
    }
}
