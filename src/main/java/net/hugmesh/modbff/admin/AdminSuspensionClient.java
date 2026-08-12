package net.hugmesh.modbff.admin;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Reactive client of hugmesh-admin-bff-api's access-suspension surface. A MOD ban
 * does NOT write Casdoor or the homeserver directly — it writes the
 * {@code access_suspension} DESIRED-STATE in admin-bff (which owns the route-access DB
 * + the single-writer reconcile loop), and the loop converges Casdoor membership +
 * the homeserver suspend state from that table. mod-bff is therefore a CLIENT of
 * admin-bff for the ban write, exactly as it is a client of federation-api for the
 * moderation queue.
 *
 * <p>Endpoints (matched field-for-field to admin-bff {@code AdminController}):
 * <ul>
 *   <li>{@code POST   /bff/admin/access-roles/{role}/{user}} — write an active
 *       access_suspension row (+ optional {@code ttlSeconds}/{@code reason}) and
 *       trigger a reconcile tick (BAN).</li>
 *   <li>{@code DELETE /bff/admin/access-roles/{role}/{user}} — CAS the active row to
 *       restored + reconcile (LIFT).</li>
 * </ul>
 *
 * <h3>Defence in depth + outcome contract</h3>
 * admin-bff's own {@code @PreAuthorize("hasRole('ADMIN')")} gates those endpoints, so
 * this client forwards the CALLER's Casdoor bearer (a MOD or ADMIN) — but admin-bff
 * requires ADMIN there. To let a MOD drive a ban WITHOUT widening the admin surface,
 * the in-cluster wiring presents this BFF's mTLS service identity (see
 * {@link AdminApiConfig}); the actual cross-service trust + the MOD→ban authorisation
 * stay enforced at mod-bff's own method/service gate ({@code ModService}) + the
 * gateway route rules. Either way the WRITE is the only effect here.
 *
 * <p>Wrapped in {@code @CircuitBreaker(name="admin-bff")}: a stalled/erroring admin-bff
 * trips the breaker and the fallback returns {@link SuspensionOutcome#degraded} —
 * NEVER a success — so the ban endpoint degrades to a 202 pending, never a 200
 * blocked. The local {@code mod_action} audit row is still written by the caller.
 */
public class AdminSuspensionClient {

    private static final Logger log = LoggerFactory.getLogger(AdminSuspensionClient.class);

    private final WebClient http;

    public AdminSuspensionClient(final WebClient webClient) {
        this.http = webClient;
    }

    /**
     * Write the access_suspension desired-state (BAN). Returns
     * {@link SuspensionOutcome#PENDING} on a successful write (the reconcile loop will
     * apply it); a breaker-open/errored admin-bff returns {@code degraded:...} via the
     * {@link #suspendFallback fallback} — never a success.
     *
     * @param role       {@code ROLE_MATRIX} | {@code ROLE_MASTODON} | {@code PROFILE}
     * @param user       the user being banned
     * @param ttlSeconds optional auto-restore TTL; null = permanent
     * @param reason     optional audit note
     */
    @CircuitBreaker(name = "admin-bff", fallbackMethod = "suspendFallback")
    public Mono<SuspensionOutcome> suspend(String role, String user, Long ttlSeconds, String reason) {
        return suspend(role, user, ttlSeconds, reason, List.of(), false);
    }

    /**
     * Write the access_suspension desired-state (BAN) ALSO carrying the service-scoped
     * {@code @system} notification directive (Notifications PR6): {@code notifyChannels}
     * (already platform-scoped by mod-bff) + {@code emailOnly}. admin-bff's
     * SuspensionService stamps the notification_outbox row from this — reason/ttl/target +
     * the directive, but NEVER an actor.
     *
     * <p><b>No actor in the body.</b> The body carries only the effect parameters + the
     * fan-out directive; the moderator's identity is DELIBERATELY absent, so the neutral
     * {@code @system} sender can never expose who moderated (the no-mod-identity rule). The
     * caller's bearer/mTLS identity is for AUTHN of the cross-service call, not for the
     * notification content.
     */
    @CircuitBreaker(name = "admin-bff", fallbackMethod = "suspendNotifyFallback")
    public Mono<SuspensionOutcome> suspend(String role, String user, Long ttlSeconds, String reason,
                                           List<String> notifyChannels, boolean emailOnly) {
        Map<String, Object> body = new LinkedHashMap<>();
        if (ttlSeconds != null) body.put("ttlSeconds", ttlSeconds);
        if (reason != null) body.put("reason", reason);
        if (notifyChannels != null && !notifyChannels.isEmpty()) body.put("notifyChannels", notifyChannels);
        if (emailOnly) body.put("notifyEmailOnly", true);
        return http.post()
                .uri("/bff/admin/access-roles/{role}/{user}", role, user)
                .bodyValue(body)
                .retrieve()
                .toBodilessEntity()
                .doOnSuccess(r -> log.info("[admin-bff] access-suspension WRITTEN role={} user={} ttl={} notify={}",
                        role, user, ttlSeconds, notifyChannels))
                .thenReturn(SuspensionOutcome.PENDING);
    }

    /** Clear the active suspension (LIFT). Same degraded-not-success contract as {@link #suspend}. */
    @CircuitBreaker(name = "admin-bff", fallbackMethod = "clearFallback")
    public Mono<SuspensionOutcome> clear(String role, String user) {
        return http.delete()
                .uri("/bff/admin/access-roles/{role}/{user}", role, user)
                .retrieve()
                .toBodilessEntity()
                .doOnSuccess(r -> log.info("[admin-bff] access-suspension CLEARED role={} user={}", role, user))
                .thenReturn(SuspensionOutcome.PENDING);
    }

    // ── Circuit-breaker fallbacks (degraded, never success) ────────────
    @SuppressWarnings("unused")
    private Mono<SuspensionOutcome> suspendFallback(String role, String user, Long ttlSeconds,
                                                    String reason, Throwable t) {
        log.warn("[admin-bff] access-suspension WRITE degraded role={} user={} — {}", role, user, t.toString());
        return Mono.just(SuspensionOutcome.degraded(t.getClass().getSimpleName()));
    }

    @SuppressWarnings("unused")
    private Mono<SuspensionOutcome> suspendNotifyFallback(String role, String user, Long ttlSeconds,
                                                          String reason, List<String> notifyChannels,
                                                          boolean emailOnly, Throwable t) {
        log.warn("[admin-bff] access-suspension WRITE degraded role={} user={} — {}", role, user, t.toString());
        return Mono.just(SuspensionOutcome.degraded(t.getClass().getSimpleName()));
    }

    @SuppressWarnings("unused")
    private Mono<SuspensionOutcome> clearFallback(String role, String user, Throwable t) {
        log.warn("[admin-bff] access-suspension CLEAR degraded role={} user={} — {}", role, user, t.toString());
        return Mono.just(SuspensionOutcome.degraded(t.getClass().getSimpleName()));
    }
}
