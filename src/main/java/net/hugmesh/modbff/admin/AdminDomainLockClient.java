package net.hugmesh.modbff.admin;

import io.github.resilience4j.circuitbreaker.annotation.CircuitBreaker;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reactive client of hugmesh-admin-bff-api's DOMAIN-LOCK surface — the ADD-semantics
 * sibling of {@link AdminSuspensionClient} (which drives the REMOVE-semantics
 * access-suspension surface). A MOD does NOT write Casdoor or the homeserver
 * force-local set directly: it writes the {@code domain_lock} DESIRED-STATE in
 * admin-bff (which owns that table + the single-writer reconcile loop), and the loop
 * converges the {@code ROLE_MATRIX_DOMAINLOCKED}/{@code ROLE_MASTODON_DOMAINLOCKED}
 * markers + the homeserver/egress force-local enforcement from that table.
 *
 * <p><b>ADD-semantics, NOT a suspension.</b> Domain-lock is an ADDITIVE marker: the
 * locked user KEEPS {@code ROLE_MATRIX}/{@code ROLE_MASTODON} (the gateway routes are
 * untouched) and merely gains the {@code *_DOMAINLOCKED} marker that forces their
 * traffic local-only. It is therefore a SEPARATE admin-bff table from
 * {@code access_suspension} (whose REMOVE-semantics + closed role pattern make
 * overloading unsafe), reached through a SEPARATE endpoint.
 *
 * <p>Endpoints (matched to the admin-bff {@code AdminController} domain-lock surface,
 * which is keyed by {@code platform = matrix|mastodon}):
 * <ul>
 *   <li>{@code POST   /bff/admin/domain-lock/{platform}/{user}} — write an active
 *       {@code domain_lock} row (+ optional {@code reason}) and trigger a reconcile
 *       tick (LOCK).</li>
 *   <li>{@code DELETE /bff/admin/domain-lock/{platform}/{user}} — CAS the active row to
 *       removed + reconcile (UNLOCK).</li>
 * </ul>
 *
 * <h3>Defence in depth + outcome contract</h3>
 * admin-bff re-checks its own {@code @PreAuthorize} scope on those endpoints; this
 * client forwards the CALLER's Casdoor bearer (a MOD or ADMIN) over the same mTLS
 * service identity {@link AdminSuspensionClient} uses (see {@link AdminApiConfig}), so
 * the cross-service trust + the MOD→domain-lock authorisation stay enforced at
 * mod-bff's own service gate ({@code ModService}'s below-them guard) + the gateway
 * route rules. The WRITE is the only effect here.
 *
 * <p>Wrapped in {@code @CircuitBreaker(name="admin-bff")} (shared with the suspension
 * client): a stalled/erroring admin-bff trips the breaker and the fallback returns
 * {@link SuspensionOutcome#degraded} — NEVER a success — so the domain-lock endpoint
 * degrades to a 202 pending, never a 200 locked. The local {@code mod_action} audit
 * row is still written by the caller.
 */
public class AdminDomainLockClient {

    private static final Logger log = LoggerFactory.getLogger(AdminDomainLockClient.class);

    private final WebClient http;

    public AdminDomainLockClient(final WebClient webClient) {
        this.http = webClient;
    }

    /**
     * Write the {@code domain_lock} desired-state (LOCK). Returns
     * {@link SuspensionOutcome#PENDING} on a successful write (the reconcile loop will
     * apply it); a breaker-open/errored admin-bff returns {@code degraded:...} via the
     * {@link #lockFallback fallback} — never a success.
     *
     * @param platform {@code matrix} | {@code mastodon}
     * @param user     the user being domain-locked (forced local-only)
     * @param reason   optional audit note
     */
    @CircuitBreaker(name = "admin-bff", fallbackMethod = "lockFallback")
    public Mono<SuspensionOutcome> lock(String platform, String user, String reason) {
        Map<String, Object> body = new LinkedHashMap<>();
        if (reason != null) body.put("reason", reason);
        return http.post()
                .uri("/bff/admin/domain-lock/{platform}/{user}", platform, user)
                .bodyValue(body)
                .retrieve()
                .toBodilessEntity()
                .doOnSuccess(r -> log.info("[admin-bff] domain-lock WRITTEN platform={} user={}", platform, user))
                .thenReturn(SuspensionOutcome.PENDING);
    }

    /** Clear the active domain-lock (UNLOCK). Same degraded-not-success contract as {@link #lock}. */
    @CircuitBreaker(name = "admin-bff", fallbackMethod = "unlockFallback")
    public Mono<SuspensionOutcome> unlock(String platform, String user) {
        return http.delete()
                .uri("/bff/admin/domain-lock/{platform}/{user}", platform, user)
                .retrieve()
                .toBodilessEntity()
                .doOnSuccess(r -> log.info("[admin-bff] domain-lock CLEARED platform={} user={}", platform, user))
                .thenReturn(SuspensionOutcome.PENDING);
    }

    // ── Circuit-breaker fallbacks (degraded, never success) ────────────
    @SuppressWarnings("unused")
    private Mono<SuspensionOutcome> lockFallback(String platform, String user, String reason, Throwable t) {
        log.warn("[admin-bff] domain-lock WRITE degraded platform={} user={} — {}", platform, user, t.toString());
        return Mono.just(SuspensionOutcome.degraded(t.getClass().getSimpleName()));
    }

    @SuppressWarnings("unused")
    private Mono<SuspensionOutcome> unlockFallback(String platform, String user, Throwable t) {
        log.warn("[admin-bff] domain-lock CLEAR degraded platform={} user={} — {}", platform, user, t.toString());
        return Mono.just(SuspensionOutcome.degraded(t.getClass().getSimpleName()));
    }
}
