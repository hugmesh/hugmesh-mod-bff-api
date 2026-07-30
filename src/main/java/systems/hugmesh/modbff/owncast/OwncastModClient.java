package systems.hugmesh.modbff.owncast;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.modbff.external.BlockOutcome;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reactive client of hugmesh-owncast-bff-api's MODERATION surface — the effector
 * behind the central {@code /bff/mod/owncast/**} leg. owncast-bff OWNS the live-stream
 * moderation state (ban/restore reuse its {@code owncast_grant} desired-state; hide
 * flips {@code owncast_stream.visibility}) and its own local
 * {@code owncast_moderation_audit} journal; this client drives those endpoints so the
 * SAME action is ALSO recorded in this BFF's central {@code mod_action} ledger
 * ({@code owncast.hide} / {@code owncast.kill} / {@code owncast.restore}, platform
 * {@code owncast}) — the cross-repo wiring the owncast-bff README deferred.
 *
 * <p>Endpoints (matched to the owncast-bff {@code OwncastModerationController}):
 * <ul>
 *   <li>{@code POST /bff/owncast/mod/streams/{ownerSubject}/hide} — force the target
 *       owner's stream {@code visibility=internal} (HIDE).</li>
 *   <li>{@code POST /bff/owncast/mod/streams/{ownerSubject}/ban} — KILL: write an
 *       active {@code owncast_grant(banned)} + hide (owncast-bff's kill verb rides its
 *       {@code /ban} path).</li>
 *   <li>{@code POST /bff/owncast/mod/streams/{ownerSubject}/restore} — CAS the active
 *       ban active→revoked (no auto-republish).</li>
 * </ul>
 *
 * <h3>Trust + outcome contract</h3>
 * The CALLER's Casdoor bearer is forwarded (see {@link OwncastApiConfig}) over the same
 * mTLS client-presentation seam the federation/admin-bff clients use, so owncast-bff
 * re-derives the moderator identity + brand from the SAME validated token and re-checks
 * its own path gate + {@code @PreAuthorize} (defence in depth). UNLIKE the admin-bff
 * desired-state writers, the owncast effect is SYNCHRONOUS — a 2xx means the
 * hide/kill/restore ALREADY landed, so a success maps to {@link BlockOutcome#OK}
 * (the controller may return 200 applied).
 *
 * <p>HONESTY: a 404 (the target has no stream in the moderator's brand) propagates as a
 * real {@link ApiException#notFound} — no action happened, so NO ledger row is written
 * and the moderator sees the truth. Any other failure (breaker-open, 5xx, timeout)
 * resolves to {@code degraded:<reason>} via the {@code @CircuitBreaker} fallback —
 * NEVER a success — and the caller records the honest outcome on the ledger row
 * (there is NO reconcile loop on this surface; a degraded call must be retried).
 */
public class OwncastModClient {

    private static final Logger log = LoggerFactory.getLogger(OwncastModClient.class);

    private final WebClient http;

    public OwncastModClient(final WebClient webClient) {
        this.http = webClient;
    }

    /** HIDE the target owner's stream (force internal). See class contract. */
    @CircuitBreaker(name = "owncast-bff", fallbackMethod = "actFallback")
    public Mono<BlockOutcome> hide(String ownerSubject, String reason) {
        return act("hide", ownerSubject, reason);
    }

    /** KILL the target owner (active banned grant + hide) — owncast-bff's {@code /ban} path. */
    @CircuitBreaker(name = "owncast-bff", fallbackMethod = "actFallback")
    public Mono<BlockOutcome> kill(String ownerSubject, String reason) {
        return act("ban", ownerSubject, reason);
    }

    /** RESTORE the target owner (CAS the active ban to revoked; no auto-republish). */
    @CircuitBreaker(name = "owncast-bff", fallbackMethod = "actFallback")
    public Mono<BlockOutcome> restore(String ownerSubject, String reason) {
        return act("restore", ownerSubject, reason);
    }

    /** One moderation POST; a 2xx is a SYNCHRONOUSLY-applied effect → {@link BlockOutcome#OK}. */
    private Mono<BlockOutcome> act(String verb, String ownerSubject, String reason) {
        Map<String, Object> body = new LinkedHashMap<>();
        if (reason != null) body.put("reason", reason);
        return http.post()
                .uri("/bff/owncast/mod/streams/{ownerSubject}/" + verb, ownerSubject)
                .bodyValue(body)
                .retrieve()
                // A 404 is a REAL contract answer (no stream for this owner in this
                // brand) — surface it as a 404, don't degrade it into a retryable blur.
                .onStatus(s -> s.value() == 404, r -> Mono.error(ApiException.notFound(
                        "target has no owncast stream in the moderator's brand")))
                .toBodilessEntity()
                .doOnSuccess(r -> log.info("[owncast-bff] mod {} APPLIED owner={}", verb, ownerSubject))
                .thenReturn(BlockOutcome.OK);
    }

    // ── Circuit-breaker fallback (degraded, never success) ─────────────
    /**
     * Shared fallback for hide/kill/restore. A REAL 4xx contract answer (the 404 mapped
     * in {@link #act}) is re-propagated so the moderator sees it; everything else
     * (breaker-open, connect failure, 5xx) collapses to {@code degraded:<reason>} —
     * the effect did NOT land and the caller must say so.
     */
    @SuppressWarnings("unused")
    private Mono<BlockOutcome> actFallback(String ownerSubject, String reason, Throwable t) {
        if (t instanceof ApiException) {
            return Mono.error(t);
        }
        log.warn("[owncast-bff] mod call degraded owner={} — {}", ownerSubject, t.toString());
        return Mono.just(BlockOutcome.degraded(t.getClass().getSimpleName()));
    }
}
