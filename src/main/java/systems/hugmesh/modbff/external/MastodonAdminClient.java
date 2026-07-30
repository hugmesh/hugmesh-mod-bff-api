package systems.hugmesh.modbff.external;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatusCode;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

/**
 * Reactive admin client for the Mastodon-API fediverse server (akkoma) — wired
 * against the in-cluster service {@code http://akkoma.hugmesh-backend.svc
 * .cluster.local:4000} (overridable via {@code external.mastodon.base-url};
 * default grounded in hugmesh-generator manifests/akkoma/akkoma.yaml).
 *
 * <h3>WIRED external call — akkoma pleroma-admin, dark by default</h3>
 * <p>akkoma (a Pleroma fork) exposes its moderation REST surface under
 * {@code /api/v1/pleroma/admin/**} (legacy alias {@code /api/pleroma/admin/**}). The
 * confirmed, idempotent verbs this client drives are:
 * <ul>
 *   <li><b>block-user</b> → {@code PATCH /api/v1/pleroma/admin/users/deactivate}
 *       with body {@code {"nicknames":["<localpart>"]}} (a JSON array even for one
 *       user). Deactivate is an <i>absolute set</i> (not a toggle), so re-issuing on
 *       an already-deactivated user is a natural 200 no-op — idempotent and safe to
 *       reconcile. NOTE: there is NO {@code /users/{nick}/suspend} verb in
 *       Pleroma/Akkoma (the old javadoc was wrong), and {@code toggle_activation}
 *       must be avoided because it flips state per call.</li>
 *   <li><b>block-instance</b> → {@code DELETE /api/v1/pleroma/admin/instances/{host}}.
 *       This kicks off a background purge of all users + activities from that remote
 *       instance (the closest admin-API "block"; true soft domain-block is MRF
 *       SimplePolicy config, not a REST verb). Re-issuing on an already-purged or
 *       unknown instance is a success/no-op, treated as OK.</li>
 * </ul>
 *
 * <p>The call stays <b>dark</b> until {@code external.mastodon.enabled=true} AND an
 * admin bearer is present ({@code external.mastodon.admin-token}, sourced from Vault
 * {@code hugmesh/akkoma-admin} property {@code token} via ESO — placeholder/empty
 * default, never inlined). When disabled (the default) {@link #doBlock} short-circuits
 * to {@link BlockOutcome#STUBBED} and issues NO HTTP, so a homeserver-less cluster is
 * inert. The caller ALWAYS records the action in the {@code mod_action} audit table
 * regardless of this outcome, so even a stubbed block is fully auditable.
 *
 * <p><b>Live-stack verification (2026-07, compose stack; mainline Mastodon 4.3.1
 * standing in for Akkoma):</b> the pleroma-admin verbs themselves remain Akkoma-only
 * (mainline has NO {@code /api/v1/pleroma/*} routes — route-level 404 — so their happy
 * path still needs a real Akkoma). What IS live-verified is the honest degrade
 * envelope with {@code external.mastodon.enabled=true} pointed at that stack:
 * <ul>
 *   <li>block-user vs the 404ing endpoint → {@code degraded:http-404}, never OK
 *       (pre-fix this was a FALSE "ok" via the 404-swallow);</li>
 *   <li>block-user/block-instance vs Mastodon's force-HTTPS redirect (308) on the plain-HTTP
 *       port → {@code degraded:http-308}, never OK (pre-fix a 3xx slipped through
 *       {@code retrieve()} as a false OK);</li>
 *   <li>block-instance 404 stays OK by design — Akkoma already-purged idempotency —
 *       which is exactly why the flag must only ever target a real Akkoma.</li>
 * </ul>
 */
public class MastodonAdminClient {

    private static final Logger log = LoggerFactory.getLogger(MastodonAdminClient.class);

    /** Confirmed idempotent pleroma-admin deactivate (absolute set) — see class javadoc. */
    static final String DEACTIVATE_PATH = "/api/v1/pleroma/admin/users/deactivate";
    /** Confirmed pleroma-admin remote-instance purge — see class javadoc. */
    static final String INSTANCE_PATH = "/api/v1/pleroma/admin/instances/{host}";

    private final WebClient http;
    private final boolean enabled;
    private final String adminToken;

    public MastodonAdminClient(final WebClient webClient, boolean enabled, String adminToken) {
        this.http = webClient;
        this.enabled = enabled;
        this.adminToken = adminToken == null ? "" : adminToken;
    }

    /**
     * Block/suspend a fediverse account, server-wide. {@code acct} may be a bare
     * localpart or a full {@code @user@instance}; the local nickname (the part before
     * the {@code @instance}, leading {@code @} stripped) is what the deactivate verb
     * takes. Wrapped in {@code @CircuitBreaker(name="akkoma")}: a stalled/erroring
     * akkoma trips the breaker and {@link #blockFallback} returns {@code degraded} —
     * NEVER {@link BlockOutcome#OK} — so the caller returns 202 pending, never 200.
     */
    @CircuitBreaker(name = "akkoma", fallbackMethod = "blockFallback")
    public Mono<BlockOutcome> blockUser(String acct) {
        log.info("[mastodon] block-user acct={} (enabled={})", acct, enabled);
        return doBlock("block-user", acct);
    }

    /** Block/defederate (purge) a remote fediverse instance/domain, server-wide (breaker-guarded). */
    @CircuitBreaker(name = "akkoma", fallbackMethod = "blockFallback")
    public Mono<BlockOutcome> blockInstance(String domain) {
        log.info("[mastodon] block-instance domain={} (enabled={})", domain, enabled);
        return doBlock("block-instance", domain);
    }

    /** Breaker-open / error fallback — degraded, NEVER OK (so the caller stays at 202 pending). */
    @SuppressWarnings("unused")
    private Mono<BlockOutcome> blockFallback(String target, Throwable t) {
        log.warn("[mastodon] block for {} degraded (breaker/err): {}", target, t.toString());
        return Mono.just(BlockOutcome.degraded(t.getClass().getSimpleName()));
    }

    /**
     * The single external-call seam. Dark by default: when {@code enabled=false} (the
     * platform default) it returns {@link BlockOutcome#STUBBED} and issues NO HTTP, so
     * merging is inert. When enabled (and an admin token is present) it issues the
     * confirmed idempotent pleroma-admin call and swallows already-applied as OK.
     */
    private Mono<BlockOutcome> doBlock(String op, String target) {
        if (!enabled) {
            return Mono.just(BlockOutcome.STUBBED);
        }
        if (adminToken.isBlank()) {
            // Enabled but no Vault/ESO admin token wired — do NOT issue an unauthenticated
            // call; degrade so the caller stays 202 pending (never a false 200 blocked).
            log.warn("[mastodon] {} for {} skipped — external.mastodon.admin-token is blank "
                    + "(expected from Vault hugmesh/akkoma-admin via ESO)", op, target);
            return Mono.just(BlockOutcome.degraded("no-admin-token"));
        }
        return switch (op) {
            case "block-user" -> deactivateUser(target);
            case "block-instance" -> purgeInstance(target);
            default -> Mono.just(BlockOutcome.degraded("unknown-op"));
        };
    }

    /**
     * PATCH /api/v1/pleroma/admin/users/deactivate with {@code {"nicknames":[localpart]}}.
     * Idempotent absolute set — already-deactivated re-issue is a natural 200 OK, which is
     * exactly why ANY non-2xx here (incl. 404) DEGRADES, never OK: deactivate succeeds with
     * 200 even when already applied, so a 404 can only mean the route or the user is
     * MISSING (live-verified 2026-07 against the compose stack, where mainline Mastodon
     * 4.3.1 has no {@code /api/v1/pleroma/*} routes at all — the pre-fix 404-swallow
     * turned that route-level 404 into a FALSE "ok"). Non-2xx-but-non-error statuses
     * (e.g. Mastodon's force-HTTPS 308 redirect on the plain-HTTP port, also live-verified to
     * slip through as a false OK before this fix) are raised to errors explicitly.
     */
    private Mono<BlockOutcome> deactivateUser(String acct) {
        String nickname = localpart(acct);
        return http.patch()
                .uri(DEACTIVATE_PATH)
                .header("Authorization", "Bearer " + adminToken)
                .bodyValue(Map.of("nicknames", List.of(nickname)))
                .retrieve()
                .onStatus(s -> !s.is2xxSuccessful(), org.springframework.web.reactive.function.client.ClientResponse::createException)
                .toBodilessEntity()
                .thenReturn(BlockOutcome.OK)
                .onErrorResume(WebClientResponseException.class, this::degradeHttp);
    }

    /**
     * DELETE /api/v1/pleroma/admin/instances/{host} — background purge of the remote
     * instance. Re-issue on an already-purged/unknown instance is a 404 no-op, treated OK
     * (this idempotent swallow is AKKOMA semantics: it presumes the pleroma-admin route
     * exists, so the flag must never be flipped against a non-Akkoma target — on the
     * compose stack's mainline Mastodon the route-level 404 is indistinguishable from
     * already-purged). Any other non-2xx (incl. the force-HTTPS 308 redirect, live-verified)
     * degrades, never OK.
     */
    private Mono<BlockOutcome> purgeInstance(String domain) {
        return http.delete()
                .uri(INSTANCE_PATH, domain)
                .header("Authorization", "Bearer " + adminToken)
                .retrieve()
                .onStatus(s -> !s.is2xxSuccessful(), org.springframework.web.reactive.function.client.ClientResponse::createException)
                .toBodilessEntity()
                .thenReturn(BlockOutcome.OK)
                .onErrorResume(WebClientResponseException.class, this::swallowAlreadyPurged);
    }

    /**
     * INSTANCE leg only: swallow the idempotent already-purged 404 as OK (Akkoma
     * semantics — see {@link #purgeInstance}); every other status degrades (never OK)
     * so the caller stays 202 pending-reconcile — this mirrors the
     * {@code @CircuitBreaker} fallback for the per-call (non-breaker-open) error path.
     */
    private Mono<BlockOutcome> swallowAlreadyPurged(WebClientResponseException e) {
        HttpStatusCode status = e.getStatusCode();
        if (status.value() == 404) {
            log.info("[mastodon] instance already-purged/unknown ({}), treating as OK", status);
            return Mono.just(BlockOutcome.OK);
        }
        return degradeHttp(e);
    }

    /** Degrade on any HTTP-level failure — NEVER OK, so the caller stays 202 pending. */
    private Mono<BlockOutcome> degradeHttp(WebClientResponseException e) {
        log.warn("[mastodon] admin call failed ({}), degrading (never OK)", e.getStatusCode());
        return Mono.just(BlockOutcome.degraded("http-" + e.getStatusCode().value()));
    }

    /**
     * Reduce an {@code acct} to the akkoma local nickname the deactivate verb takes:
     * strip a leading {@code @}, drop any {@code @instance} suffix, THEN fold to the nickname
     * the account was actually PROVISIONED under (see {@link #mastodonNickname}).
     */
    static String localpart(String acct) {
        String s = acct == null ? "" : acct.trim();
        if (s.startsWith("@")) {
            s = s.substring(1);
        }
        int at = s.indexOf('@');
        String local = at >= 0 ? s.substring(0, at) : s;
        return mastodonNickname(local);
    }

    /**
     * Fold a bare local part to the akkoma NICKNAME the account was provisioned under — mirrors
     * {@code ServiceTokenBroker.mastodonLocalpart} in the BFFs (akkoma/Mastodon nicknames allow
     * only {@code [a-z0-9_]} and cap at 30 chars). Provisioning mints/records the account under
     * this fold, so a moderation deactivate that targeted the RAW local part (e.g. a dotted Gmail
     * localpart {@code alice.smith}, hyphens, {@code =}/{@code /}, or {@code >30} chars) would hit
     * a nickname that does not exist → 404 → the client degrades (never OK) and the desired-state
     * row stays {@code pending-reconcile} forever, so the ban never applies. Folding here makes
     * the deactivate target the real account. Idempotent — an already-folded nickname (the common
     * {@code @user@instance} case) is unchanged.
     */
    static String mastodonNickname(String local) {
        String base = (local == null ? "user" : local).toLowerCase(Locale.ROOT);
        String cleaned = base.replaceAll("[^a-z0-9_]", "_");
        if (cleaned.length() > 30) {
            cleaned = cleaned.substring(0, 30);
        }
        return cleaned.replaceAll("_", "").isEmpty() ? "user" : cleaned;
    }
}
