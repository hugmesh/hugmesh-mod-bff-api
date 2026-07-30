package systems.hugmesh.modbff.external;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Reactive admin client for the Matrix homeserver (tuwunel) — wired against the
 * in-cluster service {@code http://tuwunel.hugmesh-backend.svc.cluster.local
 * :8008} (overridable via {@code external.matrix.base-url}; default grounded in
 * hugmesh-generator manifests/tuwunel/tuwunel.yaml).
 *
 * <h3>⚠️ STUBBED external call — honest deferral (verified contract)</h3>
 * <p>tuwunel is a Conduit-family server and, per the generator manifest + upstream
 * source, has <b>NO Synapse-style {@code /_synapse/admin} REST API and no HTTP admin
 * surface at all</b>. Server-admin verbs are {@code !admin ...} text commands posted
 * as {@code m.room.message} events into the auto-created admin room
 * ({@code #admins:hugmesh.systems}); an in-process bot reads them and replies
 * <i>asynchronously</i> with another room event. The verified verbs are:
 * <ul>
 *   <li><b>deactivate</b>: {@code !admin users deactivate @<localpart>:<server>}
 *       (UserCommand::Deactivate) — posted via the ordinary client/server send-message
 *       endpoint {@code PUT /_matrix/client/v3/rooms/{adminRoomId}/send/m.room.message/{txnId}}.</li>
 *   <li><b>re-activate</b>: <b>DOES NOT EXIST</b> — tuwunel has only Deactivate/
 *       DeactivateAll, no Activate verb; un-block must be modelled out of band.</li>
 *   <li><b>per-instance/server federation block</b>: <b>not a runtime command</b> —
 *       only per-room {@code !admin federation disable-room/enable-room}, while whole-
 *       server blocking is static {@code forbidden_remote_server_names} config (reload
 *       only). The authoritative Matrix per-user/server backstop is the generator
 *       egress NetworkPolicy, not a BFF call.</li>
 * </ul>
 *
 * <p>Therefore this leg ships as a <b>flag-gated structured stub</b> (the researched
 * recommendation): the {@link #doBlock(String, String)} seam returns
 * {@link BlockOutcome#STUBBED} (never OK) so the caller stays 202 pending and the
 * desired-state row remains authority. A real wire-up would need a persistent logged-in
 * Matrix identity (token lifecycle), admin-room alias→room_id resolution, per-message
 * txn ids, and async-reply correlation (the HTTP 200 only ACKs the post, not the
 * effect) — essentially a small Matrix client, deliberately NOT half-built here.
 * <ul>
 *   <li>the reactive {@link WebClient} is wired + ready ({@link #http});</li>
 *   <li>the block call is NOT made — {@link #blockUser} / {@link #blockInstance}
 *       return {@link BlockOutcome#STUBBED} after logging the intended action.</li>
 * </ul>
 * The caller ALWAYS records the action in the {@code mod_action} audit table
 * regardless of this outcome, so a stubbed block is still fully auditable.
 */
public class MatrixAdminClient {

    private static final Logger log = LoggerFactory.getLogger(MatrixAdminClient.class);

    @SuppressWarnings("unused") // wired and ready for future Matrix-client wire-up (see class Javadoc)
    private final WebClient http;
    private final boolean enabled;

    public MatrixAdminClient(final WebClient webClient, boolean enabled) {
        this.http = webClient;
        this.enabled = enabled;
    }

    /**
     * Block (ban network-wide) a Matrix user by MXID, server-wide. Wrapped in
     * {@code @CircuitBreaker(name="tuwunel")}: once the real call is wired (see
     * {@link #doBlock}), a stalled/erroring tuwunel trips the breaker and the
     * {@link #blockFallback fallback} returns {@code degraded} — NEVER {@link BlockOutcome#OK} —
     * so the caller returns 202 pending, never 200 blocked.
     */
    @CircuitBreaker(name = "tuwunel", fallbackMethod = "blockFallback")
    public Mono<BlockOutcome> blockUser(String mxid) {
        log.info("[matrix] block-user mxid={} (enabled={})", mxid, enabled);
        return doBlock("block-user", mxid);
    }

    /** Block (defederate) a remote Matrix instance/domain, server-wide (breaker-guarded). */
    @CircuitBreaker(name = "tuwunel", fallbackMethod = "blockFallback")
    public Mono<BlockOutcome> blockInstance(String domain) {
        log.info("[matrix] block-instance domain={} (enabled={})", domain, enabled);
        return doBlock("block-instance", domain);
    }

    /** Breaker-open / error fallback — degraded, NEVER OK (so the caller stays at 202 pending). */
    @SuppressWarnings("unused")
    private Mono<BlockOutcome> blockFallback(String target, Throwable t) {
        log.warn("[matrix] block for {} degraded (breaker/err): {}", target, t.toString());
        return Mono.just(BlockOutcome.degraded(t.getClass().getSimpleName()));
    }

    /**
     * The single external-call seam. STUBBED by design: tuwunel has no HTTP admin API
     * — server-admin verbs are async admin-room bot commands needing a persistent
     * Matrix client + reply correlation (see class javadoc), so a real wire-up is out
     * of scope for this reactive WebClient. Even when {@code enabled=true} we return
     * {@link BlockOutcome#STUBBED} (never OK) so the caller stays 202 pending-reconcile.
     * The intended transport (for a future Matrix-client effort) is:
     *
     * <pre>{@code
     *   // tuwunel (Conduit-family) — NO REST admin API. Post the bot command as an
     *   // m.room.message into the admin room, then correlate the ASYNC reply event
     *   // (the HTTP 200 only ACKs the post, not the deactivation effect):
     *   //   PUT /_matrix/client/v3/rooms/{adminRoomId}/send/m.room.message/{txnId}
     *   //   {"msgtype":"m.text","body":"!admin users deactivate @localpart:server"}
     *   // NOTE: there is NO "!admin users activate" verb, and whole-server federation
     *   // block is static forbidden_remote_server_names config — egress NetworkPolicy
     *   // is the authoritative per-user/server backstop. See hugmesh-generator
     *   // manifests/tuwunel/admin-sync-job.yaml for the proven transport + ESO token.
     * }</pre>
     */
    private Mono<BlockOutcome> doBlock(String op, String target) {
        if (!enabled) {
            return Mono.just(BlockOutcome.STUBBED);
        }
        // enabled=true but tuwunel has no callable admin API (admin-room bot only) →
        // STUBBED, logged loudly so an operator who flips the flag knows a dedicated
        // Matrix-client wire-up (not a REST call) is the next step.
        log.warn("[matrix] {} for {} is STUBBED — tuwunel exposes no HTTP admin API "
                + "(admin-room bot command only); a Matrix-client wire-up is required", op, target);
        return Mono.just(BlockOutcome.STUBBED);
    }
}
