package net.hugmesh.modbff.external;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;

/**
 * Reactive admin client for the Matrix homeserver (tuwunel) — wired against the
 * in-cluster service {@code http://tuwunel.hugmesh-backend.svc.cluster.local
 * :8008} (overridable via {@code external.matrix.base-url}; default grounded in
 * hugmesh-generator specs/cluster/manifests/tuwunel/tuwunel.yaml).
 *
 * <h3>Reachability, since decision 51 (2026-09-18)</h3>
 * <p>{@link #blockUser} (the {@code !admin users deactivate} transport below) is no
 * longer called by {@code ModService}'s MOD-facing block surface: a MOD-initiated
 * Matrix USER block is now applied as a reversible {@code domain_lock} write instead
 * (see {@code ModService#matrixUserBlock}), because deactivate is irreversible and
 * tuwunel has no {@code activate}. This reverses decision 5 ("ANSWERED 2026-09-10:
 * deactivate"). The method and the transport below are UNCHANGED and kept for a future
 * ADMIN-only path with its own explicit confirmation — none exists yet, tracked on
 * hugmesh-mod-bff-api#23 — so today {@link #blockUser} is unreachable from anywhere in
 * this service. Do not arm {@code MATRIX_ADMIN_ENABLED} before that path exists.
 *
 * <h3>Admin-room command transport — dark by default, dormant on the MOD path</h3>
 * <p>tuwunel is a Conduit-family server and, per the generator manifest + upstream
 * source, has <b>NO Synapse-style {@code /_synapse/admin} REST API and no HTTP admin
 * surface at all</b>. Server-admin verbs are {@code !admin ...} text commands posted
 * as {@code m.room.message} events into the auto-created admin room
 * ({@code admin_room_default}, {@code #admins:hugmesh.net} in the generator manifest);
 * an in-process bot reads them and replies <i>asynchronously</i> with another room
 * event. What this client does when {@code external.matrix.enabled=true} AND an admin
 * bearer is present ({@code external.matrix.admin-token}, Vault
 * {@code hugmesh/tuwunel-admin} property {@code token} via the ESO ExternalSecret
 * {@code tuwunel-admin} — the SAME secret the generator's tuwunel-admin-sync Job
 * mounts):
 * <ol>
 *   <li>resolve the admin-room alias to a room id once per process
 *       ({@code GET /_matrix/client/v3/directory/room/{alias}}, cached; the cache is
 *       dropped on any HTTP failure so a recreated room re-resolves);</li>
 *   <li>post {@code !admin users deactivate @localpart:server} as an {@code m.text}
 *       message with a fresh transaction id
 *       ({@code PUT /_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}});</li>
 *   <li>return {@link BlockOutcome#posted(String) posted:&lt;event_id&gt;} — which is
 *       deliberately <b>NOT</b> {@link BlockOutcome#OK}: the HTTP 200 only ACKs that
 *       the command MESSAGE was accepted into the room, not that the bot applied it.
 *       The caller therefore stays at 202 pending-reconcile, and the event id lands in
 *       the {@code mod_action} audit row as the correlation handle.</li>
 * </ol>
 *
 * <h3>What is still deferred (see README "Honest deferrals" / "Roadmap")</h3>
 * <ul>
 *   <li><b>Reply correlation.</b> The bot's asynchronous reply (an {@code m.notice}
 *       in the admin room, expected to carry {@code m.relates_to.m.in_reply_to} =
 *       the posted event id) is not yet read back, so an outcome never upgrades from
 *       {@code posted} to {@code ok}. Its success/failure text grammar must be pinned
 *       against the deployed tuwunel before any code claims {@code ok}.</li>
 *   <li><b>block-instance (operator decision 50, 2026-09-18, answer B).</b> tuwunel
 *       has NO runtime per-server federation-block verb (only per-room
 *       {@code !admin federation disable-room}); whole-server blocking is a STATIC
 *       {@code forbidden_remote_server_names} config edit + a GitOps reconcile + a
 *       homeserver restart — not something an HTTP call from here can do. So the
 *       instance leg returns {@code requested:no-tuwunel-verb} when enabled — a
 *       durably-recorded REQUEST (the {@code mod_action} row), never implying the
 *       block was applied. Turning that request into the config edit is a SEPARATE
 *       admin/GitOps job, out of scope for this repo — filed as follow-up issues on
 *       hugmesh-federation-api and hugmesh-generator, cross-linked from
 *       hugmesh-mod-bff-api#1. The generator egress NetworkPolicy remains the
 *       authoritative backstop in the meantime.</li>
 *   <li><b>Un-block.</b> There is no {@code !admin users activate} verb; lifting a
 *       Matrix block must be modelled out of band.</li>
 * </ul>
 * When {@code enabled=false} (the platform default) every call returns
 * {@link BlockOutcome#STUBBED} and issues NO HTTP, so a homeserver-less run is inert.
 * The caller ALWAYS records the action in the {@code mod_action} audit table
 * regardless of outcome.
 */
public class MatrixAdminClient {

    private static final Logger log = LoggerFactory.getLogger(MatrixAdminClient.class);

    /** Alias → room id lookup (client-server spec; the alias is percent-encoded by WebClient). */
    static final String DIRECTORY_PATH = "/_matrix/client/v3/directory/room/{alias}";
    /** Spec send path — PUT with a per-message txnId (the generator's POST scaffold is non-spec). */
    static final String SEND_PATH = "/_matrix/client/v3/rooms/{roomId}/send/m.room.message/{txnId}";
    /** The confirmed tuwunel verb (UserCommand::Deactivate); takes a full MXID. */
    static final String DEACTIVATE_COMMAND = "!admin users deactivate ";

    /**
     * MXID grammar guard. The command is a single TEXT line the admin bot splits into
     * clap-style arguments, so whitespace or a newline inside the target would inject
     * extra arguments (e.g. {@code --no-leave-rooms}) or a second command line. Only a
     * plain {@code @localpart:server[:port]} is ever interpolated.
     */
    private static final Pattern MXID = Pattern.compile("^@[A-Za-z0-9._=/+-]+:[A-Za-z0-9.-]+(?::\\d{1,5})?$");
    private static final ParameterizedTypeReference<Map<String, Object>> JSON = new ParameterizedTypeReference<>() { };

    private final WebClient http;
    private final boolean enabled;
    private final String adminToken;
    private final String serverName;
    private final String adminRoomAlias;
    /** Resolved admin-room id, cached per process; cleared on any HTTP failure. */
    private final AtomicReference<String> adminRoomId = new AtomicReference<>();

    public MatrixAdminClient(final WebClient webClient, boolean enabled, String adminToken,
                             String serverName, String adminRoomAlias) {
        this.http = webClient;
        this.enabled = enabled;
        this.adminToken = adminToken == null ? "" : adminToken.trim();
        this.serverName = serverName == null ? "" : serverName.trim();
        this.adminRoomAlias = adminRoomAlias == null ? "" : adminRoomAlias.trim();
    }

    /**
     * Block (deactivate) a Matrix user by MXID (a bare localpart is qualified to
     * {@code @localpart:<server-name>}), server-wide. Wrapped in
     * {@code @CircuitBreaker(name="tuwunel")}: a stalled/erroring tuwunel trips the
     * breaker and the {@link #blockFallback fallback} returns {@code degraded} — NEVER
     * {@link BlockOutcome#OK} — so the caller returns 202 pending, never 200 blocked.
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
     * The single external-call seam. Dark by default: {@code enabled=false} returns
     * {@link BlockOutcome#STUBBED} with NO HTTP. Enabled without an admin token degrades
     * ({@code no-admin-token}) rather than posting unauthenticated. Enabled with a token,
     * {@code block-user} is reachable only from a future admin path (see class javadoc —
     * the MOD path no longer calls it) and posts the real admin-room command;
     * {@code block-instance} has no tuwunel verb at all and records a REQUEST
     * ({@code requested:no-tuwunel-verb}) rather than attempting an effect.
     */
    private Mono<BlockOutcome> doBlock(String op, String target) {
        if (!enabled) {
            return Mono.just(BlockOutcome.STUBBED);
        }
        if (adminToken.isBlank()) {
            log.warn("[matrix] {} for {} skipped — external.matrix.admin-token is blank "
                    + "(expected from Vault hugmesh/tuwunel-admin via ESO secret tuwunel-admin)", op, target);
            return Mono.just(BlockOutcome.degraded("no-admin-token"));
        }
        return switch (op) {
            case "block-user" -> deactivateUser(target);
            case "block-instance" -> noInstanceVerb(target);
            default -> Mono.just(BlockOutcome.degraded("unknown-op"));
        };
    }

    /** Resolve the admin room, post the deactivate command, map to posted/degraded (never OK). */
    private Mono<BlockOutcome> deactivateUser(String target) {
        String mxid = mxid(target);
        if (mxid == null) {
            log.warn("[matrix] block-user target '{}' is not a plain MXID — refusing to interpolate it "
                    + "into an admin-room command (degraded:bad-target)", target);
            return Mono.just(BlockOutcome.degraded("bad-target"));
        }
        String command = DEACTIVATE_COMMAND + mxid;
        return resolveAdminRoom()
                .flatMap(roomId -> sendCommand(roomId, command))
                .switchIfEmpty(Mono.fromSupplier(() -> noAdminRoom(mxid)))
                .onErrorResume(WebClientResponseException.class, e -> degradeHttp(e, mxid));
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

    /** Alias → room id, cached per process; empty when the directory reply carries no room id. */
    private Mono<String> resolveAdminRoom() {
        String cached = adminRoomId.get();
        if (cached != null) {
            return Mono.just(cached);
        }
        return http.get()
                .uri(DIRECTORY_PATH, adminRoomAlias)
                .header("Authorization", "Bearer " + adminToken)
                .retrieve()
                .onStatus(s -> !s.is2xxSuccessful(), ClientResponse::createException)
                .bodyToMono(JSON)
                .flatMap(this::roomIdOf)
                .doOnNext(adminRoomId::set);
    }

    private Mono<String> roomIdOf(Map<String, Object> body) {
        Object id = body.get("room_id");
        if (id instanceof String s && s.startsWith("!")) {
            return Mono.just(s);
        }
        return Mono.empty();
    }

    /** PUT the command as an m.text message with a fresh txnId; map the event id to posted. */
    private Mono<BlockOutcome> sendCommand(String roomId, String command) {
        String txnId = "modbff-" + UUID.randomUUID();
        return http.put()
                .uri(SEND_PATH, roomId, txnId)
                .header("Authorization", "Bearer " + adminToken)
                .bodyValue(Map.of("msgtype", "m.text", "body", command))
                .retrieve()
                .onStatus(s -> !s.is2xxSuccessful(), ClientResponse::createException)
                .bodyToMono(JSON)
                .defaultIfEmpty(Map.of())
                .map(body -> postedOutcome(body, command));
    }

    private BlockOutcome postedOutcome(Map<String, Object> body, String command) {
        Object id = body.get("event_id");
        if (id instanceof String s && !s.isBlank()) {
            log.info("[matrix] admin-room command posted ({}): '{}' — effect is asynchronous and NOT yet "
                    + "correlated; caller stays pending", s, command);
            return BlockOutcome.posted(s);
        }
        log.warn("[matrix] admin-room send returned 2xx without an event_id for '{}' — degrading", command);
        return BlockOutcome.degraded("no-event-id");
    }

    private BlockOutcome noAdminRoom(String mxid) {
        log.warn("[matrix] admin room alias '{}' did not resolve to a room id — cannot post the deactivate "
                + "for {} (degraded:no-admin-room)", adminRoomAlias, mxid);
        return BlockOutcome.degraded("no-admin-room");
    }

    /** Degrade on any HTTP-level failure — NEVER OK — and drop the cached room id so we re-resolve. */
    private Mono<BlockOutcome> degradeHttp(WebClientResponseException e, String mxid) {
        adminRoomId.set(null);
        log.warn("[matrix] admin-room call for {} failed ({}), degrading (never OK)", mxid, e.getStatusCode());
        return Mono.just(BlockOutcome.degraded("http-" + e.getStatusCode().value()));
    }

    /**
     * Normalise a moderator-supplied target to a full MXID, or {@code null} when it is
     * not one: {@code @user:server} passes through; {@code user:server} gains the
     * {@code @}; a bare {@code user} is qualified to {@code @user:<server-name>}.
     * Anything that still fails the {@link #MXID} grammar (whitespace, newlines, shell
     * characters) is rejected so it can never widen the admin-room command.
     */
    String mxid(String target) {
        String s = target == null ? "" : target.trim();
        if (s.isEmpty()) {
            return null;
        }
        if (!s.startsWith("@")) {
            s = "@" + s;
        }
        if (s.indexOf(':') < 0) {
            if (serverName.isBlank()) {
                return null;
            }
            s = s + ":" + serverName;
        }
        return MXID.matcher(s).matches() ? s : null;
    }
}
