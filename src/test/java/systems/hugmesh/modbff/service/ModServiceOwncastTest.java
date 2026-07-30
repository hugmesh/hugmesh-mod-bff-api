package systems.hugmesh.modbff.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.commons.web.ApiException;
import systems.hugmesh.modbff.admin.AdminDomainLockClient;
import systems.hugmesh.modbff.admin.AdminSuspensionClient;
import systems.hugmesh.modbff.admin.CasdoorRoleClient;
import systems.hugmesh.modbff.audit.ModAction;
import systems.hugmesh.modbff.audit.ModActionRepository;
import systems.hugmesh.modbff.external.BlockOutcome;
import systems.hugmesh.modbff.owncast.OwncastModClient;

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
 * Service-layer guards + honest-outcome contract for the OWNCAST moderation leg
 * (the {@code /bff/mod/owncast/**} central wiring). Mirrors {@code ModServiceTest}'s
 * delineation for ban/block:
 * <ul>
 *   <li>PUNITIVE actions (hide/kill) run the FULL guard chain — self → same-tenant →
 *       privileged — ALL BEFORE the owncast-bff effector call or the ledger row;</li>
 *   <li>REMEDIAL restore mirrors lift: only the cross-tenant proof applies;</li>
 *   <li>the ledger row records the HONEST effector outcome ({@code ok} /
 *       {@code degraded:<reason>}), stamped with the caller's issuer-derived domain;</li>
 *   <li>a 404 (no stream) propagates and writes NO ledger row — no action happened.</li>
 * </ul>
 */
class ModServiceOwncastTest {

    AdminSuspensionClient suspensions;
    AdminDomainLockClient domainLocks;
    CasdoorRoleClient roles;
    ModActionRepository audit;
    systems.hugmesh.modbff.external.MatrixAdminClient matrix;
    systems.hugmesh.modbff.external.MastodonAdminClient mastodon;
    OwncastModClient owncast;
    ModService service;

    private static Authentication auth(String name, String... authorities) {
        return new UsernamePasswordAuthenticationToken(
                name, "n/a", AuthorityUtils.createAuthorityList(authorities));
    }

    private static ModAction row(String action, String domain) {
        return new ModAction("id-1", "mod:bob", action, "owncast", "streamer:carol", null, "ok",
                LocalDateTime.parse("2026-06-06T00:00:00"), null, null, null, null, domain);
    }

    @BeforeEach
    void setUp() {
        suspensions = mock(AdminSuspensionClient.class);
        domainLocks = mock(AdminDomainLockClient.class);
        roles = mock(CasdoorRoleClient.class);
        audit = mock(ModActionRepository.class);
        matrix = mock(systems.hugmesh.modbff.external.MatrixAdminClient.class);
        mastodon = mock(systems.hugmesh.modbff.external.MastodonAdminClient.class);
        owncast = mock(OwncastModClient.class);
        service = new ModService(suspensions, domainLocks, roles, audit, matrix, mastodon, owncast);
        // Defaults: target is NOT privileged, tenant membership provable, effector OK,
        // and the domain-aware 7-arg record(...) persists a row.
        when(roles.isPrivileged(anyString(), any())).thenReturn(Mono.just(false));
        when(roles.belongsToDomain(anyString(), any())).thenReturn(Mono.just(true));
        when(owncast.hide(anyString(), any())).thenReturn(Mono.just(BlockOutcome.OK));
        when(owncast.kill(anyString(), any())).thenReturn(Mono.just(BlockOutcome.OK));
        when(owncast.restore(anyString(), any())).thenReturn(Mono.just(BlockOutcome.OK));
        when(audit.record(anyString(), anyString(), anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(row("owncast.hide", "default")));
    }

    // ── PUNITIVE guards: self / privileged / cross-tenant → 403, NO effect ──

    @Test
    void selfKill_isForbidden_andNoEffect() {
        StepVerifier.create(service.owncastKill("mod:bob", null, auth("mod:bob", "ROLE_MOD")))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status().value()).isEqualTo(403);
                })
                .verify();
        // Rejected BEFORE the Casdoor lookup, the effector call, and the ledger row.
        verify(roles, never()).isPrivileged(anyString(), any());
        verify(owncast, never()).kill(anyString(), any());
        verify(audit, never()).record(anyString(), anyString(), anyString(), anyString(),
                any(), anyString(), anyString());
    }

    @Test
    void selfHide_isForbidden() {
        StepVerifier.create(service.owncastHide("mod:bob", null, auth("mod:bob", "ROLE_MOD")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(owncast, never()).hide(anyString(), any());
    }

    @Test
    void killPrivilegedTarget_isForbidden_andNoEffect() {
        when(roles.isPrivileged(eq("anadmin"), any())).thenReturn(Mono.just(true));
        StepVerifier.create(service.owncastKill("anadmin", null, auth("mod:bob", "ROLE_MOD")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(owncast, never()).kill(anyString(), any());
        verify(audit, never()).record(anyString(), anyString(), anyString(), anyString(),
                any(), anyString(), anyString());
    }

    @Test
    void hide_crossTenantTarget_isForbidden_failClosed_andNoEffect() {
        when(roles.belongsToDomain(eq("victim-of-brandy"), eq("brandx"))).thenReturn(Mono.just(false));
        StepVerifier.create(service.owncastHide("victim-of-brandy", null,
                        auth("mod:x", "ROLE_MOD", "DOMAIN_brandx")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        // The deny short-circuits BEFORE the privileged read, the effector, the row.
        verify(roles, never()).isPrivileged(anyString(), any());
        verify(owncast, never()).hide(anyString(), any());
        verify(audit, never()).record(anyString(), anyString(), anyString(), anyString(),
                any(), anyString(), anyString());
    }

    // ── REMEDIAL restore mirrors lift: tenant proof only ─────────────────────

    @Test
    void restore_crossTenantTarget_isForbidden() {
        when(roles.belongsToDomain(eq("victim-of-brandy"), eq("brandx"))).thenReturn(Mono.just(false));
        StepVerifier.create(service.owncastRestore("victim-of-brandy", null,
                        auth("mod:x", "ROLE_MOD", "DOMAIN_brandx")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(owncast, never()).restore(anyString(), any());
    }

    @Test
    void restore_skipsSelfAndPrivilegedGuards_likeLift() {
        // A restore is remedial (mirrors lift): no self/privileged gate, so the
        // privileged lookup is never consulted and the restore proceeds.
        StepVerifier.create(service.owncastRestore("streamer:carol", null, auth("mod:bob", "ROLE_MOD")))
                .expectNextCount(1)
                .verifyComplete();
        verify(roles, never()).isPrivileged(anyString(), any());
        verify(owncast).restore(eq("streamer:carol"), any());
    }

    // ── Happy path: synchronous OK + honest ledger row with domain stamp ──────

    @Test
    void hide_appliesSynchronously_andRecordsOkRowWithDomainStamp() {
        when(audit.record(anyString(), anyString(), anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(row("owncast.hide", "brandx")));
        when(roles.belongsToDomain(eq("streamer:carol"), eq("brandx"))).thenReturn(Mono.just(true));
        StepVerifier.create(service.owncastHide("streamer:carol", "off-topic",
                        auth("mod:x", "ROLE_MOD", "DOMAIN_brandx")))
                .assertNext(r -> {
                    assertThat(r.outcome().isOk()).isTrue();
                    assertThat(r.body().get("state")).isEqualTo("applied");
                })
                .verifyComplete();
        verify(owncast).hide(eq("streamer:carol"), eq("off-topic"));
        verify(audit).record(eq("mod:x"), eq("owncast.hide"), eq("owncast"),
                eq("streamer:carol"), eq("off-topic"), eq("ok"), eq("brandx"));
    }

    @Test
    void kill_recordsOwncastKillVerb() {
        StepVerifier.create(service.owncastKill("streamer:dave", "abuse", auth("mod:bob", "ROLE_MOD")))
                .expectNextCount(1)
                .verifyComplete();
        verify(audit).record(eq("mod:bob"), eq("owncast.kill"), eq("owncast"),
                eq("streamer:dave"), eq("abuse"), eq("ok"), eq("default"));
    }

    // ── HONESTY: degraded effector → not-applied envelope + degraded row ──────

    @Test
    void kill_whenOwncastBffDegraded_isNotApplied_butIntentIsLedgered() {
        when(owncast.kill(anyString(), any()))
                .thenReturn(Mono.just(BlockOutcome.degraded("CallNotPermittedException")));
        StepVerifier.create(service.owncastKill("streamer:dave", null, auth("mod:bob", "ROLE_MOD")))
                .assertNext(r -> {
                    // NEVER a fake success: the body says not-applied + carries the reason
                    // and the no-reconcile-loop retry note.
                    assertThat(r.outcome().isOk()).isFalse();
                    assertThat(r.body().get("state")).isEqualTo("not-applied");
                    assertThat(r.body().get("external").toString()).startsWith("degraded:");
                    assertThat(r.body().get("note").toString()).contains("NO reconcile loop");
                })
                .verifyComplete();
        // The moderator's intent is still auditable — the row records the honest outcome.
        verify(audit).record(eq("mod:bob"), eq("owncast.kill"), eq("owncast"),
                eq("streamer:dave"), any(), eq("degraded:CallNotPermittedException"), eq("default"));
    }

    // ── HONESTY: a 404 (no stream) propagates; nothing is ledgered ────────────

    @Test
    void hide_targetWithoutStream_propagates404_andNoLedgerRow() {
        when(owncast.hide(eq("ghost"), any()))
                .thenReturn(Mono.error(ApiException.notFound(
                        "target has no owncast stream in the moderator's brand")));
        StepVerifier.create(service.owncastHide("ghost", null, auth("mod:bob", "ROLE_MOD")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(404))
                .verify();
        verify(audit, never()).record(anyString(), anyString(), anyString(), anyString(),
                any(), anyString(), anyString());
    }

    // ── SUPERADMIN bypasses the tenant proof (cross-domain control plane) ─────

    @Test
    void kill_superadminCrossBrand_bypassesTenantGuard() {
        StepVerifier.create(service.owncastKill("streamer-of-brandy", null,
                        auth("super:root", "ROLE_SUPERADMIN", "DOMAIN_brandx")))
                .expectNextCount(1)
                .verifyComplete();
        verify(roles, never()).belongsToDomain(anyString(), any());
        verify(owncast).kill(eq("streamer-of-brandy"), any());
    }
}
