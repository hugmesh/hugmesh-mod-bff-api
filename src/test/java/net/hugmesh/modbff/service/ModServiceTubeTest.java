package net.hugmesh.modbff.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.modbff.admin.AdminDomainLockClient;
import net.hugmesh.modbff.admin.AdminSuspensionClient;
import net.hugmesh.modbff.admin.CasdoorRoleClient;
import net.hugmesh.modbff.audit.ModAction;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.audit.ModActionType;
import net.hugmesh.modbff.external.BlockOutcome;
import net.hugmesh.modbff.owncast.OwncastModClient;
import net.hugmesh.modbff.tube.TubeModClient;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The tube hide leg of {@link ModService}: the tube-moderator role check, the punitive
 * guard chain, and the honest-outcome ledger contract. Mirrors
 * {@code ModServiceOwncastTest}.
 */
class ModServiceTubeTest {

    CasdoorRoleClient roles;
    ModActionRepository audit;
    TubeModClient tube;
    ModService service;

    private static Authentication auth(String name, String... authorities) {
        return new UsernamePasswordAuthenticationToken(
                name, "n/a", AuthorityUtils.createAuthorityList(authorities));
    }

    private static Authentication tubeMod(String name) {
        return auth(name, "ROLE_MOD", "ROLE_TUBE", "DOMAIN_brandx");
    }

    private static ModAction row() {
        return new ModAction("id-1", "mod:bob", "tube.hide", "tube", "uploader:carol", null, "ok",
                LocalDateTime.parse("2026-10-15T00:00:00"), null, null, null, null, "brandx");
    }

    private ModService serviceWith(TubeModClient client) {
        return new ModService(mock(AdminSuspensionClient.class), mock(AdminDomainLockClient.class),
                roles, audit, mock(net.hugmesh.modbff.external.MatrixAdminClient.class),
                mock(net.hugmesh.modbff.external.MastodonAdminClient.class),
                mock(OwncastModClient.class), null, client);
    }

    @BeforeEach
    void setUp() {
        roles = mock(CasdoorRoleClient.class);
        audit = mock(ModActionRepository.class);
        tube = mock(TubeModClient.class);
        service = serviceWith(tube);
        when(roles.isPrivileged(anyString(), any())).thenReturn(Mono.just(false));
        when(roles.belongsToDomain(anyString(), any())).thenReturn(Mono.just(true));
        when(tube.hide(anyString(), any())).thenReturn(Mono.just(BlockOutcome.OK));
        when(audit.record(anyString(), anyString(), anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(row()));
    }

    private static void assertForbidden(Throwable e) {
        assertThat(e).isInstanceOf(ApiException.class);
        assertThat(((ApiException) e).status().value()).isEqualTo(403);
    }

    private void assertNoEffect() {
        verify(tube, never()).hide(anyString(), any());
        verify(audit, never()).record(anyString(), anyString(), anyString(), anyString(),
                any(), anyString(), anyString());
    }

    // ── role: MOD and TUBE, checked before anything else ────────────────

    @Test
    void modWithoutTube_isForbidden_andNoEffect() {
        StepVerifier.create(service.tubeHide("uploader:carol", null, auth("mod:bob", "ROLE_MOD", "DOMAIN_brandx")))
                .expectErrorSatisfies(ModServiceTubeTest::assertForbidden).verify();
        verify(roles, never()).isPrivileged(anyString(), any());
        assertNoEffect();
    }

    @Test
    void tubeWithoutMod_isForbidden_andNoEffect() {
        StepVerifier.create(service.tubeHide("uploader:carol", null, auth("u:bob", "ROLE_TUBE", "DOMAIN_brandx")))
                .expectErrorSatisfies(ModServiceTubeTest::assertForbidden).verify();
        assertNoEffect();
    }

    // ── guards: self / privileged / cross-tenant → 403, NO effect ───────

    @Test
    void selfHide_isForbidden_andNoEffect() {
        StepVerifier.create(service.tubeHide("mod:bob", null, tubeMod("mod:bob")))
                .expectErrorSatisfies(ModServiceTubeTest::assertForbidden).verify();
        verify(roles, never()).isPrivileged(anyString(), any());
        assertNoEffect();
    }

    @Test
    void privilegedTarget_isForbidden_andNoEffect() {
        when(roles.isPrivileged(eq("anadmin"), any())).thenReturn(Mono.just(true));
        StepVerifier.create(service.tubeHide("anadmin", null, tubeMod("mod:bob")))
                .expectErrorSatisfies(ModServiceTubeTest::assertForbidden).verify();
        assertNoEffect();
    }

    @Test
    void crossTenantTarget_isForbidden_andNoEffect() {
        when(roles.belongsToDomain(eq("uploader:carol"), any())).thenReturn(Mono.just(false));
        StepVerifier.create(service.tubeHide("uploader:carol", null, tubeMod("mod:bob")))
                .expectErrorSatisfies(ModServiceTubeTest::assertForbidden).verify();
        assertNoEffect();
    }

    // ── outcome: ledgered honestly, domain-stamped ──────────────────────

    @Test
    void okOutcome_isLedgeredWithTubePlatform_andDomainStamp() {
        StepVerifier.create(service.tubeHide("uploader:carol", "spam", tubeMod("mod:bob")))
                .assertNext(r -> {
                    assertThat(r.applied()).isTrue();
                    assertThat(r.action().action()).isEqualTo("tube.hide");
                })
                .verifyComplete();
        verify(tube).hide("uploader:carol", "spam");
        verify(audit).record("mod:bob", ModActionType.TUBE_HIDE, "tube", "uploader:carol",
                "spam", "ok", "brandx");
    }

    @Test
    void degradedOutcome_isLedgeredVerbatim_andNotApplied() {
        when(tube.hide(anyString(), any())).thenReturn(Mono.just(BlockOutcome.degraded("Timeout")));
        StepVerifier.create(service.tubeHide("uploader:carol", null, tubeMod("mod:bob")))
                .assertNext(r -> assertThat(r.applied()).isFalse())
                .verifyComplete();
        verify(audit).record("mod:bob", ModActionType.TUBE_HIDE, "tube", "uploader:carol",
                null, "degraded:Timeout", "brandx");
    }

    @Test
    void effectorError_writesNoLedgerRow() {
        when(tube.hide(anyString(), any())).thenReturn(Mono.error(ApiException.notFound("no content")));
        StepVerifier.create(service.tubeHide("uploader:carol", null, tubeMod("mod:bob")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404))
                .verify();
        verify(audit, never()).record(anyString(), anyString(), anyString(), anyString(),
                any(), anyString(), anyString());
    }

    @Test
    void noTubeClient_refusesToRun_andWritesNothing() {
        ModService unwired = serviceWith(null);
        StepVerifier.create(unwired.tubeHide("uploader:carol", null, tubeMod("mod:bob")))
                .expectError(IllegalStateException.class).verify();
        verify(audit, never()).record(anyString(), anyString(), anyString(), anyString(),
                any(), anyString(), anyString());
    }
}
