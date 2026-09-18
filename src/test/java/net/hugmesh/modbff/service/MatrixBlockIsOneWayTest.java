package net.hugmesh.modbff.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.modbff.admin.AdminDomainLockClient;
import net.hugmesh.modbff.admin.AdminSuspensionClient;
import net.hugmesh.modbff.admin.CasdoorRoleClient;
import net.hugmesh.modbff.admin.SuspensionOutcome;
import net.hugmesh.modbff.audit.ModAction;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.external.BlockOutcome;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.external.MatrixAdminClient;
import net.hugmesh.modbff.owncast.OwncastModClient;

import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * A MATRIX BLOCK IS ONE-WAY, AND NOTHING IN THIS SERVICE CAN UNDO IT — the measured
 * asymmetry behind hugmesh-mod-bff-api#1(b), pinned so it is a guard rather than only
 * prose in a javadoc.
 *
 * <p><b>What is measured.</b> {@code MatrixAdminClient} is reached from exactly one place,
 * {@code ModService.block(...)} (the {@code case MATRIX} routing at {@code ModService:264}),
 * and the only verb it can post is {@code !admin users deactivate} — tuwunel has no
 * {@code !admin users activate}. {@code lift(...)} and {@code domainUnlock(...)}, the two
 * calls a moderator would reach for to reverse something, clear Casdoor / admin-bff
 * DESIRED-STATE only and never touch a homeserver client at all. So once the transport is
 * armed and a block has been posted, this BFF has no path that lifts it.
 *
 * <p>Independently corroborated in a sibling repo: hugmesh-admin-bff-api's
 * {@code homeserver/HomeserverAdminClient} models its own re-activate leg as
 * {@code activate(no-tuwunel-verb)} and says in its javadoc that there is "NO activate
 * command at all". <b>Neither is primary evidence</b> — no run against a live tuwunel has
 * ever been made, and none is possible in this lane.
 *
 * <p><b>This test asserts the CURRENT state, it does not endorse it.</b> If it ever goes
 * red because an un-block path was added, that is the point: modelling the reversal is an
 * operator decision (what a lift should mean when the forward verb is irreversible), not
 * an implementation detail to slip in. See the decision proposed on hugmesh-generator#347.
 */
class MatrixBlockIsOneWayTest {

    AdminSuspensionClient suspensions;
    AdminDomainLockClient domainLocks;
    CasdoorRoleClient roles;
    ModActionRepository audit;
    MatrixAdminClient matrix;
    MastodonAdminClient mastodon;
    OwncastModClient owncast;
    ModService service;

    private static Authentication auth(String name, String... authorities) {
        return new UsernamePasswordAuthenticationToken(
                name, "n/a", AuthorityUtils.createAuthorityList(authorities));
    }

    private static ModAction row(String action) {
        return new ModAction("id-1", "mod:bob", action, "access", "alice", null, "pending",
                LocalDateTime.parse("2026-06-06T00:00:00"), "k", "user", null, "pending");
    }

    @BeforeEach
    void setUp() {
        suspensions = mock(AdminSuspensionClient.class);
        domainLocks = mock(AdminDomainLockClient.class);
        roles = mock(CasdoorRoleClient.class);
        audit = mock(ModActionRepository.class);
        matrix = mock(MatrixAdminClient.class);
        mastodon = mock(MastodonAdminClient.class);
        owncast = mock(OwncastModClient.class);
        service = new ModService(suspensions, domainLocks, roles, audit, matrix, mastodon, owncast);

        when(roles.isPrivileged(anyString(), any())).thenReturn(Mono.just(false));
        when(roles.belongsToDomain(anyString(), any())).thenReturn(Mono.just(true));
        when(suspensions.clear(anyString(), anyString())).thenReturn(Mono.just(SuspensionOutcome.PENDING));
        when(domainLocks.unlock(anyString(), anyString())).thenReturn(Mono.just(SuspensionOutcome.PENDING));
        when(audit.recordBan(anyString(), anyString(), anyString(), anyString(), anyString(),
                any(), any(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new ModActionRepository.RecordedBan(row("access.restore"), true)));
        when(audit.record(anyString(), anyString(), anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(row("matrix.block-user")));
        when(matrix.blockUser(anyString())).thenReturn(Mono.just(BlockOutcome.STUBBED));
    }

    /** The forward direction exists: a matrix block DOES reach the homeserver client. Without
     *  this the two assertions below could both pass on a service that never calls it at all. */
    @Test
    void block_doesReachTheMatrixClient() {
        StepVerifier.create(service.block("matrix", "user", "@spam:evil.example", "abuse",
                        auth("mod:bob", "ROLE_MOD", "ROLE_MATRIX", "DOMAIN_default")))
                .expectNextCount(1)
                .verifyComplete();
        verify(matrix).blockUser("@spam:evil.example");
    }

    /** Lifting a ban clears desired-state only — it cannot un-deactivate a Matrix account. */
    @Test
    void lift_neverReachesAnyHomeserverClient() {
        StepVerifier.create(service.lift("matrix", "alice", null,
                        auth("mod:bob", "ROLE_MOD", "ROLE_MATRIX", "DOMAIN_default")))
                .expectNextCount(1)
                .verifyComplete();
        verifyNoInteractions(matrix);
        verifyNoInteractions(mastodon);
    }

    /** Domain-unlock likewise: marker removal, no homeserver verb. */
    @Test
    void domainUnlock_neverReachesAnyHomeserverClient() {
        StepVerifier.create(service.domainUnlock("ROLE_MATRIX_DOMAINLOCKED", "alice", null,
                        auth("mod:bob", "ROLE_MOD", "ROLE_MATRIX", "DOMAIN_default")))
                .expectNextCount(1)
                .verifyComplete();
        verifyNoInteractions(matrix);
        verifyNoInteractions(mastodon);
    }

    /** And the forward path itself has exactly one verb: nothing ever asks the client to
     *  reverse a block, because the client has no such method to call. */
    @Test
    void theMatrixClientIsNeverAskedToReverseABlock() {
        StepVerifier.create(service.block("matrix", "user", "@spam:evil.example", "abuse",
                        auth("mod:bob", "ROLE_MOD", "ROLE_MATRIX", "DOMAIN_default")))
                .expectNextCount(1)
                .verifyComplete();
        verify(matrix, never()).blockInstance(anyString());
        org.assertj.core.api.Assertions.assertThat(MatrixAdminClient.class.getMethods())
                .as("MatrixAdminClient exposes no un-block / activate verb")
                .noneMatch(m -> m.getName().toLowerCase(java.util.Locale.ROOT).contains("activate")
                        || m.getName().toLowerCase(java.util.Locale.ROOT).contains("unblock"));
    }
}
