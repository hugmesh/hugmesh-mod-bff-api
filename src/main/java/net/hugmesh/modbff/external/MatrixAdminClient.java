package net.hugmesh.modbff.external;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import reactor.core.publisher.Mono;

/**
 * Matrix homeserver (tuwunel) admin client for mod-bff. Its only verb is
 * {@link #blockInstance}: a Matrix INSTANCE block, which tuwunel cannot apply at runtime
 * and which is therefore recorded as a REQUEST (see below).
 *
 * <h3>No user deactivate here (decision 83b, 2026-09-23)</h3>
 * <p>This class used to carry {@code blockUser}, which posted the one-way tuwunel
 * admin-room command ({@code !admin users deactivate <mxid>}; tuwunel has no
 * {@code activate}). Decision 51 (2026-09-18) had already taken it off the MOD path: a
 * MOD-initiated Matrix USER block is a reversible {@code domain_lock} write (see
 * {@code ModService#matrixUserBlock}), never a deactivate. Decision 83b then moved the
 * ADMIN-only deactivate to hugmesh-admin-bff-api, behind a propose/confirm token pair
 * ({@code POST /bff/admin/matrix/deactivations/propose} then {@code .../confirm},
 * hugmesh-admin-bff-api#115), so mod-bff's dormant copy of that transport was deleted
 * (hugmesh-mod-bff-api#23). {@code MatrixAdminClientNoUserDeactivateTest} fails if a
 * user-deactivate path comes back to this class or its verb text reappears in this
 * service's code.
 *
 * <h3>block-instance (operator decision 50, 2026-09-18, answer B)</h3>
 * <p>tuwunel has NO runtime per-server federation-block verb (only per-room
 * {@code !admin federation disable-room}); whole-server blocking is a STATIC
 * {@code forbidden_remote_server_names} config edit + a GitOps reconcile + a homeserver
 * restart, not something an HTTP call from here can do. So the instance leg issues NO
 * HTTP and returns {@code requested:no-tuwunel-verb} when enabled: a durably-recorded
 * REQUEST (the {@code mod_action} row), never implying the block was applied.
 * {@code ModService} additionally files it into hugmesh-federation-api's moderation trail
 * (decisions 84a-d). The generator egress NetworkPolicy remains the authoritative backstop.
 *
 * <h3>Gates</h3>
 * <p>When {@code enabled=false} (the platform default) every call returns
 * {@link BlockOutcome#STUBBED}. Enabled without an admin token it degrades
 * ({@code no-admin-token}). The caller ALWAYS records the action in the {@code mod_action}
 * audit table regardless of outcome.
 */
public class MatrixAdminClient {

    private static final Logger log = LoggerFactory.getLogger(MatrixAdminClient.class);

    private final boolean enabled;
    private final String adminToken;

    public MatrixAdminClient(boolean enabled, String adminToken) {
        this.enabled = enabled;
        this.adminToken = adminToken == null ? "" : adminToken.trim();
    }

    /** Block (defederate) a remote Matrix instance/domain, server-wide (breaker-guarded). */
    @CircuitBreaker(name = "tuwunel", fallbackMethod = "blockFallback")
    public Mono<BlockOutcome> blockInstance(String domain) {
        log.info("[matrix] block-instance domain={} (enabled={})", domain, enabled);
        if (!enabled) {
            return Mono.just(BlockOutcome.STUBBED);
        }
        if (adminToken.isBlank()) {
            log.warn("[matrix] block-instance for {} skipped — external.matrix.admin-token is blank "
                    + "(expected from Vault hugmesh/tuwunel-admin via ESO secret tuwunel-admin)", domain);
            return Mono.just(BlockOutcome.degraded("no-admin-token"));
        }
        return noInstanceVerb(domain);
    }

    /** Breaker-open / error fallback — degraded, NEVER OK (so the caller stays at 202 pending). */
    @SuppressWarnings("unused")
    private Mono<BlockOutcome> blockFallback(String target, Throwable t) {
        log.warn("[matrix] block for {} degraded (breaker/err): {}", target, t.toString());
        return Mono.just(BlockOutcome.degraded(t.getClass().getSimpleName()));
    }

    /**
     * tuwunel has no runtime whole-server federation-block verb (only static
     * {@code forbidden_remote_server_names} config and per-room disable-room), so the
     * instance leg cannot be applied from here — no HTTP is issued, and the intent is
     * recorded as a REQUEST (never {@code degraded}: nothing failed, nothing can
     * synchronously succeed either — operator decision 50, 2026-09-18).
     */
    private Mono<BlockOutcome> noInstanceVerb(String domain) {
        log.warn("[matrix] block-instance for {} recorded as a REQUEST, not applied — tuwunel has no "
                + "runtime per-server federation-block admin verb (static forbidden_remote_server_names "
                + "only); an administrator must turn this mod_action row into a config edit + GitOps "
                + "reconcile + restart. The generator egress NetworkPolicy is the authoritative backstop "
                + "meanwhile (requested:no-tuwunel-verb)", domain);
        return Mono.just(BlockOutcome.requested("no-tuwunel-verb"));
    }
}
