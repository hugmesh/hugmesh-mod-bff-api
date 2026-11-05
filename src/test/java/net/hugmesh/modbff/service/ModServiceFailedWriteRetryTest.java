package net.hugmesh.modbff.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import reactor.core.publisher.Mono;
import net.hugmesh.modbff.admin.AdminDomainLockClient;
import net.hugmesh.modbff.admin.AdminSuspensionClient;
import net.hugmesh.modbff.admin.CasdoorRoleClient;
import net.hugmesh.modbff.admin.SuspensionOutcome;
import net.hugmesh.modbff.audit.ModAction;
import net.hugmesh.modbff.audit.ModActionRepository;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * hugmesh-mod-bff-api#27: a desired-state write that admin-bff did not accept must not be
 * stored as {@code pending}, and a retry of that write must be RE-SENT instead of being
 * deduped against the row it left behind. A write that DID land still dedups.
 *
 * <p>The admin-bff clients are stubs returning {@link SuspensionOutcome#degraded} (the
 * live 400 of #26 is fixed, so the failure is injected, not reproduced). The audit store
 * is an in-memory {@link ModActionRepository} that keeps the real ON-CONFLICT contract:
 * one row per dedup key, a second identical call is {@code fresh=false} and gets the SAME
 * row back. {@code ModActionRetryPostgresTest} proves the SQL half against Postgres.
 */
class ModServiceFailedWriteRetryTest {

    private static final String LOCK_ROLE = AdminDomainLockClient.ROLE_MATRIX_DOMAINLOCKED;
    private static final SuspensionOutcome BAD_REQUEST = SuspensionOutcome.degraded("BadRequest");

    AdminSuspensionClient suspensions;
    AdminDomainLockClient domainLocks;
    CasdoorRoleClient roles;
    InMemoryAudit audit;
    ModService service;

    private static Authentication mod() {
        return new UsernamePasswordAuthenticationToken("mod:bob", "n/a",
                AuthorityUtils.createAuthorityList("ROLE_MOD"));
    }

    @BeforeEach
    void setUp() {
        suspensions = mock(AdminSuspensionClient.class);
        domainLocks = mock(AdminDomainLockClient.class);
        roles = mock(CasdoorRoleClient.class);
        when(roles.isPrivileged(anyString(), any())).thenReturn(Mono.just(false));
        when(roles.belongsToDomain(anyString(), any())).thenReturn(Mono.just(true));
        audit = new InMemoryAudit();
        service = new ModService(suspensions, domainLocks, roles, audit,
                mock(net.hugmesh.modbff.external.MatrixAdminClient.class),
                mock(net.hugmesh.modbff.external.MastodonAdminClient.class),
                mock(net.hugmesh.modbff.owncast.OwncastModClient.class));
    }

    // ── domain-lock ───────────────────────────────────────────────────

    @Test
    void domainLock_degradedWrite_isPersistedAsFailedNotPending() {
        when(domainLocks.lock(anyString(), anyString(), any())).thenReturn(Mono.just(BAD_REQUEST));

        ModService.LockResult first = service.domainLock(LOCK_ROLE, "frank", "spam", null, mod()).block();

        assertThat(first.state()).isEqualTo("degraded:BadRequest");
        assertThat(first.deduped()).isFalse();
        // (a) the persisted row records the failure, not 'pending'.
        ModAction row = audit.only();
        assertThat(row.propagationState()).isEqualTo("failed");
        assertThat(row.result()).isEqualTo("degraded:BadRequest");
        // The response carries the same (failed) row the trail now holds.
        assertThat(first.action().propagationState()).isEqualTo("failed");
    }

    @Test
    void domainLock_retryOfFailedWrite_isResentNotDeduped() {
        when(domainLocks.lock(anyString(), anyString(), any()))
                .thenReturn(Mono.just(BAD_REQUEST), Mono.just(SuspensionOutcome.PENDING));

        service.domainLock(LOCK_ROLE, "frank", "spam", null, mod()).block();
        ModService.LockResult retry = service.domainLock(LOCK_ROLE, "frank", "spam", null, mod()).block();

        // (b) the identical second call reached admin-bff again ...
        verify(domainLocks, times(2)).lock(LOCK_ROLE, "frank", "spam");
        // ... and says so: not a dedup, not a fake pending-reconcile for an undelivered write.
        assertThat(retry.deduped()).isFalse();
        assertThat(retry.state()).isEqualTo("pending-reconcile");
        // Updated in place: still ONE row, now pending because admin-bff accepted the retry.
        assertThat(audit.rows).hasSize(1);
        assertThat(audit.only().propagationState()).isEqualTo("pending");
        assertThat(retry.action().id()).isEqualTo(audit.only().id());
    }

    @Test
    void domainLock_retryThatFailsAgain_staysFailedAndIsResentEachTime() {
        when(domainLocks.lock(anyString(), anyString(), any())).thenReturn(Mono.just(BAD_REQUEST));

        service.domainLock(LOCK_ROLE, "frank", null, null, mod()).block();
        ModService.LockResult second = service.domainLock(LOCK_ROLE, "frank", null, null, mod()).block();
        ModService.LockResult third = service.domainLock(LOCK_ROLE, "frank", null, null, mod()).block();

        verify(domainLocks, times(3)).lock(LOCK_ROLE, "frank", null);
        assertThat(second.deduped()).isFalse();
        assertThat(third.deduped()).isFalse();
        assertThat(third.state()).isEqualTo("degraded:BadRequest");
        assertThat(audit.only().propagationState()).isEqualTo("failed");
    }

    @Test
    void domainLock_healthyWriteThenRetry_stillDedupsWithoutResending() {
        when(domainLocks.lock(anyString(), anyString(), any())).thenReturn(Mono.just(SuspensionOutcome.PENDING));

        ModService.LockResult first = service.domainLock(LOCK_ROLE, "frank", null, null, mod()).block();
        ModService.LockResult retry = service.domainLock(LOCK_ROLE, "frank", null, null, mod()).block();

        // (c) a delivered write is not re-sent: one client call, the retry is a dedup.
        verify(domainLocks, times(1)).lock(LOCK_ROLE, "frank", null);
        assertThat(first.deduped()).isFalse();
        assertThat(retry.deduped()).isTrue();
        assertThat(retry.state()).isEqualTo("pending-reconcile");
        assertThat(audit.only().propagationState()).isEqualTo("pending");
        assertThat(audit.claims.get()).isZero();
    }

    // ── domain-unlock (the route measured live in #27) ────────────────

    @Test
    void domainUnlock_degradedWrite_isFailedAndRetryIsResent() {
        when(domainLocks.unlock(anyString(), anyString()))
                .thenReturn(Mono.just(BAD_REQUEST), Mono.just(SuspensionOutcome.PENDING));

        ModService.LockResult first = service.domainUnlock(LOCK_ROLE, "frank@gmail.com", null, mod()).block();
        assertThat(first.state()).isEqualTo("degraded:BadRequest");
        assertThat(audit.only().propagationState()).isEqualTo("failed");
        assertThat(audit.only().result()).isEqualTo("degraded:BadRequest");

        ModService.LockResult retry = service.domainUnlock(LOCK_ROLE, "frank@gmail.com", null, mod()).block();

        verify(domainLocks, times(2)).unlock(LOCK_ROLE, "frank@gmail.com");
        assertThat(retry.deduped()).isFalse();
        assertThat(audit.only().propagationState()).isEqualTo("pending");
    }

    @Test
    void domainUnlock_healthyWriteThenRetry_stillDedups() {
        when(domainLocks.unlock(anyString(), anyString())).thenReturn(Mono.just(SuspensionOutcome.PENDING));

        service.domainUnlock(LOCK_ROLE, "frank", null, mod()).block();
        ModService.LockResult retry = service.domainUnlock(LOCK_ROLE, "frank", null, mod()).block();

        verify(domainLocks, times(1)).unlock(LOCK_ROLE, "frank");
        assertThat(retry.deduped()).isTrue();
    }

    // ── ban / lift (same shape) ───────────────────────────────────────

    @Test
    void ban_degradedWrite_isFailedAndRetryIsResent() {
        when(suspensions.suspend(anyString(), anyString(), any(), any()))
                .thenReturn(Mono.just(BAD_REQUEST), Mono.just(SuspensionOutcome.PENDING));

        ModService.BanResult first = service.ban("matrix", "alice", null, "abuse", null, mod()).block();
        assertThat(first.state()).isEqualTo("degraded:BadRequest");
        assertThat(audit.only().propagationState()).isEqualTo("failed");

        ModService.BanResult retry = service.ban("matrix", "alice", null, "abuse", null, mod()).block();

        verify(suspensions, times(2)).suspend("ROLE_MATRIX", "alice", null, "abuse");
        assertThat(retry.deduped()).isFalse();
        assertThat(retry.state()).isEqualTo("pending-reconcile");
        assertThat(audit.only().propagationState()).isEqualTo("pending");
    }

    @Test
    void ban_healthyWriteThenRetry_stillDedups() {
        when(suspensions.suspend(anyString(), anyString(), any(), any()))
                .thenReturn(Mono.just(SuspensionOutcome.PENDING));

        service.ban("matrix", "alice", null, null, null, mod()).block();
        ModService.BanResult retry = service.ban("matrix", "alice", null, null, null, mod()).block();

        verify(suspensions, times(1)).suspend("ROLE_MATRIX", "alice", null, null);
        assertThat(retry.deduped()).isTrue();
    }

    @Test
    void lift_degradedWrite_isFailedAndRetryIsResent() {
        when(suspensions.clear(anyString(), anyString()))
                .thenReturn(Mono.just(BAD_REQUEST), Mono.just(SuspensionOutcome.PENDING));

        service.lift("matrix", "alice", null, mod()).block();
        assertThat(audit.only().propagationState()).isEqualTo("failed");

        ModService.BanResult retry = service.lift("matrix", "alice", null, mod()).block();

        verify(suspensions, times(2)).clear("ROLE_MATRIX", "alice");
        assertThat(retry.deduped()).isFalse();
        assertThat(audit.only().propagationState()).isEqualTo("pending");
    }

    @Test
    void lift_healthyWriteThenRetry_stillDedups() {
        when(suspensions.clear(anyString(), anyString())).thenReturn(Mono.just(SuspensionOutcome.PENDING));

        service.lift("matrix", "alice", null, mod()).block();
        ModService.BanResult retry = service.lift("matrix", "alice", null, mod()).block();

        verify(suspensions, times(1)).clear("ROLE_MATRIX", "alice");
        assertThat(retry.deduped()).isTrue();
    }

    // ── a retry that loses the claim to a concurrent retry does not re-send ──

    @Test
    void retry_thatLosesTheClaim_reportsDedupAndSendsNothing() {
        when(domainLocks.lock(anyString(), anyString(), any())).thenReturn(Mono.just(BAD_REQUEST));
        service.domainLock(LOCK_ROLE, "frank", null, null, mod()).block();
        audit.claimAlwaysLost = true;

        ModService.LockResult retry = service.domainLock(LOCK_ROLE, "frank", null, null, mod()).block();

        verify(domainLocks, times(1)).lock(LOCK_ROLE, "frank", null);
        assertThat(retry.deduped()).isTrue();
    }

    /**
     * In-memory stand-in for the audit store with the production dedup contract: the
     * first {@code recordBan} for a key inserts ({@code fresh=true}); every later one
     * returns the stored row ({@code fresh=false}). {@code markFailed} /
     * {@code claimFailedForRetry} mirror the repository's UPDATEs (the claim is a
     * compare-and-set on {@code propagation_state = failed}).
     */
    static final class InMemoryAudit extends ModActionRepository {

        final Map<String, ModAction> rows = new LinkedHashMap<>();
        final AtomicInteger claims = new AtomicInteger();
        boolean claimAlwaysLost;

        InMemoryAudit() {
            super(null);
        }

        @Override
        public Mono<RecordedBan> recordBan(String dedupKey, String actor, String action, String platform,
                                           String target, String reason, String banType,
                                           LocalDateTime expiresAt, String propagationState, String domain,
                                           String notifyChannels, Boolean notifyEmailOnly) {
            ModAction existing = rows.values().stream()
                    .filter(r -> dedupKey.equals(r.dedupKey()) && domain.equals(r.domain()))
                    .findFirst().orElse(null);
            if (existing != null) {
                return Mono.just(new RecordedBan(existing, false));
            }
            ModAction row = new ModAction(UUID.randomUUID().toString(), actor, action, platform, target,
                    reason, propagationState, LocalDateTime.now(), dedupKey, banType, expiresAt,
                    propagationState, domain, notifyChannels, notifyEmailOnly);
            rows.put(row.id(), row);
            return Mono.just(new RecordedBan(row, true));
        }

        @Override
        public Mono<ModAction> markFailed(String id, String result) {
            return Mono.justOrEmpty(rows.computeIfPresent(id, (k, r) -> with(r, result, PROPAGATION_FAILED)));
        }

        @Override
        public Mono<ModAction> claimFailedForRetry(String id) {
            claims.incrementAndGet();
            ModAction r = rows.get(id);
            if (claimAlwaysLost || r == null || !PROPAGATION_FAILED.equals(r.propagationState())) {
                return Mono.empty();
            }
            ModAction claimed = with(r, PROPAGATION_PENDING, PROPAGATION_PENDING);
            rows.put(id, claimed);
            return Mono.just(claimed);
        }

        @Override
        public Mono<ModAction> byId(String id) {
            return Mono.justOrEmpty(rows.get(id));
        }

        ModAction only() {
            assertThat(rows).hasSize(1);
            return rows.values().iterator().next();
        }

        private static ModAction with(ModAction r, String result, String propagationState) {
            return new ModAction(r.id(), r.actor(), r.action(), r.platform(), r.target(), r.reason(),
                    result, r.ts(), r.dedupKey(), r.banType(), r.expiresAt(), propagationState,
                    r.domain(), r.notifyChannels(), r.notifyEmailOnly());
        }
    }
}
