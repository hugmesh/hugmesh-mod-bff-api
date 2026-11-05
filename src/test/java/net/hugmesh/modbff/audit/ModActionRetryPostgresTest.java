package net.hugmesh.modbff.audit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.modbff.admin.AdminDomainLockClient;
import net.hugmesh.modbff.admin.AdminSuspensionClient;
import net.hugmesh.modbff.admin.CasdoorRoleClient;
import net.hugmesh.modbff.admin.SuspensionOutcome;
import net.hugmesh.modbff.service.ModService;
import net.hugmesh.modbff.support.PostgresSliceTestConfig;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * hugmesh-mod-bff-api#27 over the REAL Liquibase schema (Testcontainers-Postgres): the
 * {@code markFailed} / {@code claimFailedForRetry} UPDATEs, and the domain-lock flow of
 * {@link ModService} end to end against the real {@code ON CONFLICT DO NOTHING} dedup
 * (only the admin-bff client is a stub, returning {@code degraded:BadRequest}).
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, ModActionRepository.class})
class ModActionRetryPostgresTest extends PostgresTestSupport {

    @Autowired ModActionRepository repo;
    @Autowired DatabaseClient db;

    @BeforeEach
    void clean() {
        db.sql("DELETE FROM mod_action").fetch().rowsUpdated().block();
    }

    private ModAction insertPending(String key) {
        return repo.recordBan(key, "mod:bob", ModActionType.DOMAIN_LOCK, "domain-lock",
                "frank", null, "user", null, "pending", "default").block().action();
    }

    private String stateOf(String id) {
        return db.sql("SELECT propagation_state FROM mod_action WHERE id = CAST(:id AS uuid)")
                .bind("id", id).map(r -> r.get("propagation_state", String.class)).one().block();
    }

    @Test
    void markFailed_persistsReasonAndFailedState() {
        ModAction row = insertPending("k-1");

        ModAction failed = repo.markFailed(row.id(), "degraded:BadRequest").block();

        assertThat(failed.id()).isEqualTo(row.id());
        assertThat(failed.result()).isEqualTo("degraded:BadRequest");
        assertThat(failed.propagationState()).isEqualTo("failed");
        assertThat(stateOf(row.id())).isEqualTo("failed");
    }

    @Test
    void claimFailedForRetry_isACompareAndSet() {
        ModAction row = insertPending("k-2");
        // A pending (delivered) row cannot be claimed: nothing to re-send.
        assertThat(repo.claimFailedForRetry(row.id()).blockOptional()).isEmpty();

        repo.markFailed(row.id(), "degraded:BadRequest").block();
        ModAction claimed = repo.claimFailedForRetry(row.id()).block();
        assertThat(claimed.propagationState()).isEqualTo("pending");
        assertThat(claimed.result()).isEqualTo("pending");
        // A second (concurrent) claim of the same row loses: only one retry re-sends.
        assertThat(repo.claimFailedForRetry(row.id()).blockOptional()).isEmpty();
    }

    @Test
    void domainLock_failedWriteIsStoredFailed_andRetryIsResentOverRealDedup() {
        AdminDomainLockClient locks = mock(AdminDomainLockClient.class);
        when(locks.lock(anyString(), anyString(), any()))
                .thenReturn(Mono.just(SuspensionOutcome.degraded("BadRequest")), Mono.just(SuspensionOutcome.PENDING));
        CasdoorRoleClient roles = mock(CasdoorRoleClient.class);
        when(roles.isPrivileged(anyString(), any())).thenReturn(Mono.just(false));
        ModService service = new ModService(mock(AdminSuspensionClient.class), locks, roles, repo,
                mock(net.hugmesh.modbff.external.MatrixAdminClient.class),
                mock(net.hugmesh.modbff.external.MastodonAdminClient.class),
                mock(net.hugmesh.modbff.owncast.OwncastModClient.class));
        Authentication mod = new UsernamePasswordAuthenticationToken("mod:bob", "n/a",
                AuthorityUtils.createAuthorityList("ROLE_MOD"));
        String role = AdminDomainLockClient.ROLE_MATRIX_DOMAINLOCKED;

        ModService.LockResult first = service.domainLock(role, "frank", null, null, mod).block();
        assertThat(first.state()).isEqualTo("degraded:BadRequest");
        assertThat(stateOf(first.action().id())).isEqualTo("failed");

        ModService.LockResult retry = service.domainLock(role, "frank", null, null, mod).block();
        assertThat(retry.deduped()).isFalse();
        assertThat(retry.action().id()).isEqualTo(first.action().id());
        assertThat(stateOf(first.action().id())).isEqualTo("pending");

        ModService.LockResult third = service.domainLock(role, "frank", null, null, mod).block();
        assertThat(third.deduped()).isTrue();
        verify(locks, times(2)).lock(role, "frank", null);
        assertThat(db.sql("SELECT count(*) c FROM mod_action").map(r -> r.get("c", Long.class)).one().block())
                .isEqualTo(1L);
    }
}
