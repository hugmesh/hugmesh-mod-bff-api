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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

/**
 * <b>Renamed in substance, not in name, by operator decision 51 (2026-09-18, answer
 * B — AGAINST the "leave deactivate" recommendation).</b> This class used to pin that a
 * Matrix block is a permanent one-way door: {@code MatrixAdminClient} was the only
 * homeserver seam {@code ModService.block(...)} reached, its only verb was the
 * irreversible {@code !admin users deactivate}, and neither {@code lift(...)} nor
 * {@code domainUnlock(...)} touched a homeserver client — so once posted, nothing in
 * this service could undo it. That is EXACTLY the property the operator answered
 * against: <i>"This reverses decision 5"</i> (2026-09-10: "deactivate").
 *
 * <p><b>What is pinned now — the opposite property, for the MOD path specifically:</b>
 * <ul>
 *   <li>a MOD-initiated Matrix USER block ({@code ModService.block("matrix","user",...)})
 *       no longer reaches {@link MatrixAdminClient} at all — it writes the SAME
 *       {@code domain_lock} desired-state {@link ModService#domainLock} does, through
 *       {@link AdminDomainLockClient#lock};</li>
 *   <li>that write is REVERSED end to end by the SAME path a plain domain-lock uses:
 *       {@code ModService.domainUnlock("ROLE_MATRIX_DOMAINLOCKED", target, ...)} calls
 *       {@link AdminDomainLockClient#unlock}, which is the exact undo of the {@code lock}
 *       call the block issued — so "block, then domain-unlock" is a real round trip, not
 *       a door with no handle on the other side;</li>
 *   <li>the only thing {@link ModService} ever asks of {@link MatrixAdminClient} is
 *       {@code blockInstance} (decision 50's REQUEST), for any platform/scope/role
 *       combination reachable from {@code ModController}. The deactivate transport this
 *       class used to guard ({@code MatrixAdminClient.blockUser} +
 *       {@code DEACTIVATE_COMMAND}) no longer exists in this service: decision 83b
 *       (2026-09-23) moved the ADMIN-only deactivate to hugmesh-admin-bff-api behind a
 *       propose/confirm pair (hugmesh-admin-bff-api#115), and
 *       {@code MatrixAdminClientNoUserDeactivateTest} pins that it stays gone
 *       (hugmesh-mod-bff-api#23).</li>
 * </ul>
 *
 * <p><b>This test asserts the CURRENT state, it does not endorse it as the end state.</b>
 * If it ever goes red because {@link ModService} started asking {@link MatrixAdminClient}
 * for anything but an instance block, that is the point: routing MOD traffic onto an
 * irreversible transport is exactly what decision 51 forbade — it would need a new
 * decision (or a genuine, confirmation-gated ADMIN path), not a quiet revert. Neither
 * this test nor its predecessor is primary evidence against a live tuwunel — no run has
 * been made in this lane either.
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
        when(domainLocks.lock(anyString(), anyString(), any())).thenReturn(Mono.just(SuspensionOutcome.PENDING));
        when(domainLocks.unlock(anyString(), anyString())).thenReturn(Mono.just(SuspensionOutcome.PENDING));
        when(audit.recordBan(anyString(), anyString(), anyString(), anyString(), anyString(),
                any(), any(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new ModActionRepository.RecordedBan(row("access.restore"), true)));
        when(audit.record(anyString(), anyString(), anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(row("matrix.block-user")));
        when(matrix.blockInstance(anyString())).thenReturn(Mono.just(BlockOutcome.requested("no-tuwunel-verb")));
    }

    /** The forward direction is now domain-lock, not the homeserver client. */
    @Test
    void matrixUserBlock_writesADomainLock_notTheHomeserverClient() {
        StepVerifier.create(service.block("matrix", "user", "@spam:evil.example", "abuse",
                        auth("mod:bob", "ROLE_MOD", "ROLE_MATRIX", "DOMAIN_default")))
                .assertNext(result -> org.assertj.core.api.Assertions.assertThat(result.outcome())
                        .isEqualTo(BlockOutcome.DOMAIN_LOCKED))
                .verifyComplete();
        verify(domainLocks).lock("matrix", "@spam:evil.example", "abuse");
        verifyNoInteractions(matrix);
    }

    /** Nothing ModService can be asked to do (block on either scope, lift, domainLock,
     *  domainUnlock) reaches the Matrix client except the instance block; the former
     *  deactivate verb ({@code blockUser}) is gone (decision 83b). block-INSTANCE is
     *  untouched by decision 51 (it is decision 50's territory — see
     *  {@code ExternalAdminClientTest}) and legitimately still calls
     *  {@code matrix.blockInstance}. */
    @Test
    void deactivateTransport_isUnreachableFromTheModPath() {
        Authentication mod = auth("mod:bob", "ROLE_MOD", "ROLE_MATRIX", "DOMAIN_default");
        StepVerifier.create(service.block("matrix", "user", "@spam:evil.example", "abuse", mod))
                .expectNextCount(1).verifyComplete();
        StepVerifier.create(service.block("matrix", "instance", "evil.example", "abuse", mod))
                .expectNextCount(1).verifyComplete();
        StepVerifier.create(service.lift("matrix", "alice", null, mod))
                .expectNextCount(1).verifyComplete();
        StepVerifier.create(service.domainLock("ROLE_MATRIX_DOMAINLOCKED", "alice", "evasion", null, mod))
                .expectNextCount(1).verifyComplete();
        StepVerifier.create(service.domainUnlock("ROLE_MATRIX_DOMAINLOCKED", "alice", null, mod))
                .expectNextCount(1).verifyComplete();
        verify(matrix).blockInstance("evil.example");
        verifyNoMoreInteractions(matrix);
    }

    /** Reversibility end to end: the SAME target's block (domain-lock WRITE) and a
     *  domain-unlock (domain-lock CLEAR) drive the identical admin-bff platform/user
     *  pair — "block, then domain-unlock" is a genuine round trip on this platform. */
    @Test
    void domainUnlock_reversesExactlyWhatTheMatrixUserBlockWrote() {
        Authentication mod = auth("mod:bob", "ROLE_MOD", "ROLE_MATRIX", "DOMAIN_default");
        StepVerifier.create(service.block("matrix", "user", "alice", "evasion", mod))
                .expectNextCount(1).verifyComplete();
        StepVerifier.create(service.domainUnlock("ROLE_MATRIX_DOMAINLOCKED", "alice", null, mod))
                .expectNextCount(1).verifyComplete();
        verify(domainLocks).lock("matrix", "alice", "evasion");
        verify(domainLocks).unlock("matrix", "alice");
    }

    /** Lifting a BAN still clears access_suspension desired-state only — unrelated to a
     *  Matrix domain-lock and still never reaches any homeserver client. Kept from the
     *  predecessor test: lift's own contract did not change. */
    @Test
    void lift_neverReachesAnyHomeserverClient() {
        StepVerifier.create(service.lift("matrix", "alice", null,
                        auth("mod:bob", "ROLE_MOD", "ROLE_MATRIX", "DOMAIN_default")))
                .expectNextCount(1)
                .verifyComplete();
        verifyNoInteractions(matrix);
        verifyNoInteractions(mastodon);
    }

    /** MatrixAdminClient still exposes no un-block/activate verb — even if something
     *  started calling it again, there would be nothing to reverse it with. */
    @Test
    void theMatrixClientStillExposesNoUnblockVerb() {
        org.assertj.core.api.Assertions.assertThat(MatrixAdminClient.class.getMethods())
                .as("MatrixAdminClient exposes no un-block / activate verb")
                .noneMatch(m -> m.getName().toLowerCase(java.util.Locale.ROOT).contains("activate")
                        || m.getName().toLowerCase(java.util.Locale.ROOT).contains("unblock"));
    }
}
