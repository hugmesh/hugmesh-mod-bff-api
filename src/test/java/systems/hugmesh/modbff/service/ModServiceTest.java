package systems.hugmesh.modbff.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import systems.hugmesh.modbff.admin.AdminDomainLockClient;
import systems.hugmesh.modbff.admin.AdminSuspensionClient;
import systems.hugmesh.modbff.admin.CasdoorRoleClient;
import systems.hugmesh.modbff.admin.SuspensionOutcome;
import systems.hugmesh.modbff.audit.ModAction;
import systems.hugmesh.modbff.audit.ModActionRepository;
import systems.hugmesh.commons.web.ApiException;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Service-layer guard unit tests — DEFENCE IN DEPTH. These pin the authorisation
 * invariants the controller's {@code @PreAuthorize} also enforces, RE-CHECKED here so
 * a principal past a higher leg still cannot:
 * <ul>
 *   <li>ban an ADMIN (mod-bans-admin → 403);</li>
 *   <li>ban a MOD (mod-bans-mod → 403);</li>
 *   <li>ban themselves (self-ban → 403);</li>
 *   <li>block a platform without the platform role (matrix/mastodon → 403).</li>
 * </ul>
 * Plus the outcome contract: a breaker-open / degraded admin-bff still yields a
 * pending-reconcile result (never a synchronous success), and the local audit row is
 * written either way.
 */
class ModServiceTest {

    AdminSuspensionClient suspensions;
    AdminDomainLockClient domainLocks;
    CasdoorRoleClient roles;
    ModActionRepository audit;
    systems.hugmesh.modbff.external.MatrixAdminClient matrix;
    systems.hugmesh.modbff.external.MastodonAdminClient mastodon;
    systems.hugmesh.modbff.owncast.OwncastModClient owncast;
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
        matrix = mock(systems.hugmesh.modbff.external.MatrixAdminClient.class);
        mastodon = mock(systems.hugmesh.modbff.external.MastodonAdminClient.class);
        owncast = mock(systems.hugmesh.modbff.owncast.OwncastModClient.class);
        service = new ModService(suspensions, domainLocks, roles, audit, matrix, mastodon, owncast);
        // Default: target is NOT privileged, audit records a fresh row. The service now
        // calls the DOMAIN-AWARE recordBan(...) overload (trailing domain arg) and the
        // domain-aware privileged/same-tenant guards (trailing callerDomain arg).
        when(roles.isPrivileged(anyString(), any())).thenReturn(Mono.just(false));
        // Default: the target IS provably in the caller's tenant (the same-tenant guard
        // only invokes this for a BRANDED caller; default-domain callers skip it).
        when(roles.belongsToDomain(anyString(), any())).thenReturn(Mono.just(true));
        when(audit.recordBan(anyString(), anyString(), anyString(), anyString(), anyString(),
                any(), any(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new ModActionRepository.RecordedBan(row("access.suspend"), true)));
        when(suspensions.suspend(anyString(), anyString(), any(), any()))
                .thenReturn(Mono.just(SuspensionOutcome.PENDING));
        when(domainLocks.lock(anyString(), anyString(), any()))
                .thenReturn(Mono.just(SuspensionOutcome.PENDING));
        when(domainLocks.unlock(anyString(), anyString()))
                .thenReturn(Mono.just(SuspensionOutcome.PENDING));
        // block(...) happy-path defaults: the external homeserver call is STUBBED and the
        // domain-aware 7-arg record(...) writes a row.
        when(matrix.blockUser(anyString()))
                .thenReturn(Mono.just(systems.hugmesh.modbff.external.BlockOutcome.STUBBED));
        when(matrix.blockInstance(anyString()))
                .thenReturn(Mono.just(systems.hugmesh.modbff.external.BlockOutcome.STUBBED));
        when(mastodon.blockUser(anyString()))
                .thenReturn(Mono.just(systems.hugmesh.modbff.external.BlockOutcome.STUBBED));
        when(mastodon.blockInstance(anyString()))
                .thenReturn(Mono.just(systems.hugmesh.modbff.external.BlockOutcome.STUBBED));
        when(audit.record(anyString(), anyString(), anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(row("matrix.block-user")));
    }

    // ── mod-bans-admin → 403 ───────────────────────────────────────────
    @Test
    void modBansAdmin_isForbidden() {
        when(roles.isPrivileged(eq("anadmin"), any())).thenReturn(Mono.just(true));
        StepVerifier.create(service.ban("matrix", "anadmin", null, null, null, auth("mod:bob", "ROLE_MOD")))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status().value()).isEqualTo(403);
                })
                .verify();
        // No desired-state write happened for a forbidden ban.
        verify(suspensions, never()).suspend(anyString(), anyString(), any(), any());
    }

    // ── mod-bans-mod → 403 (same privileged-target guard) ──────────────
    @Test
    void modBansMod_isForbidden() {
        when(roles.isPrivileged(eq("amod"), any())).thenReturn(Mono.just(true));
        StepVerifier.create(service.ban("mastodon", "amod", null, null, null, auth("mod:bob", "ROLE_MOD")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(suspensions, never()).suspend(anyString(), anyString(), any(), any());
    }

    // ── self-ban → 403 ─────────────────────────────────────────────────
    @Test
    void selfBan_isForbidden() {
        StepVerifier.create(service.ban("matrix", "mod:bob", null, null, null, auth("mod:bob", "ROLE_MOD")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(suspensions, never()).suspend(anyString(), anyString(), any(), any());
        // Self-ban is rejected BEFORE the privileged-role lookup is even needed.
        verify(roles, never()).isPrivileged(anyString(), any());
    }

    // ── happy path → pending-reconcile + ROLE mapping + desired-state write ─
    @Test
    void ban_writesDesiredStateAndReturnsPending() {
        StepVerifier.create(service.ban("matrix", "alice", 3600L, "abuse", null, auth("mod:bob", "ROLE_MOD")))
                .assertNext(r -> {
                    assertThat(r.state()).isEqualTo("pending-reconcile");
                    assertThat(r.deduped()).isFalse();
                })
                .verifyComplete();
        // matrix → ROLE_MATRIX desired-state write with the TTL.
        verify(suspensions).suspend(eq("ROLE_MATRIX"), eq("alice"), eq(3600L), eq("abuse"));
    }

    // ── breaker-open / degraded admin-bff → still pending (never success) ──
    @Test
    void ban_whenAdminBffDegraded_stillPendingAndAudited() {
        when(suspensions.suspend(eq("ROLE_MASTODON"), eq("alice"), any(), any()))
                .thenReturn(Mono.just(SuspensionOutcome.degraded("CallNotPermittedException")));
        StepVerifier.create(service.ban("mastodon", "alice", null, null, null, auth("mod:bob", "ROLE_MOD")))
                .assertNext(r -> {
                    // NOT a 200/blocked — a degraded variant, surfaced via the pending body.
                    assertThat(r.state()).startsWith("degraded:");
                })
                .verifyComplete();
        // The local audit row was written even though admin-bff was degraded, stamped
        // with the actor's domain (no DOMAIN_ authority on this auth → "default").
        verify(audit).recordBan(anyString(), anyString(), eq("access.suspend"), eq("access"),
                eq("alice"), isNull(), eq("user"), isNull(), eq("pending"), eq("default"));
    }

    // ── dedup: a redelivery does NOT re-issue the desired-state write ──
    @Test
    void ban_dedupRetry_doesNotReissueDesiredState() {
        when(audit.recordBan(anyString(), anyString(), anyString(), anyString(), anyString(),
                any(), any(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new ModActionRepository.RecordedBan(row("access.suspend"), false)));
        StepVerifier.create(service.ban("matrix", "alice", null, null, "idem-1", auth("mod:bob", "ROLE_MOD")))
                .assertNext(r -> {
                    assertThat(r.deduped()).isTrue();
                    assertThat(r.state()).isEqualTo("pending-reconcile");
                })
                .verifyComplete();
        // The deduped retry must NOT call the desired-state write again.
        verify(suspensions, never()).suspend(anyString(), anyString(), any(), any());
    }

    // ── platform-role assertion (matrix/mastodon → 403 without the role) ──
    @Test
    void assertPlatformRole_matrixWithoutRole_throws403() {
        assertThatThrownBy(() -> service.assertPlatformRole("matrix", auth("mod:bob", "ROLE_MOD")))
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403));
    }

    @Test
    void assertPlatformRole_mastodonWithoutRole_throws403() {
        assertThatThrownBy(() -> service.assertPlatformRole("mastodon", auth("mod:bob", "ROLE_MOD")))
                .isInstanceOf(ApiException.class);
    }

    @Test
    void assertPlatformRole_matrixWithRole_ok() {
        service.assertPlatformRole("matrix", auth("mod:bob", "ROLE_MOD", "ROLE_MATRIX"));
    }

    @Test
    void assertPlatformRole_adminBypassesPlatformRole() {
        // An ADMIN may block any platform without the specific platform role.
        service.assertPlatformRole("matrix", auth("admin:carol", "ROLE_ADMIN"));
        service.assertPlatformRole("mastodon", auth("admin:carol", "ROLE_ADMIN"));
    }

    // ── lift → pending + clears desired-state ──────────────────────────
    @Test
    void lift_clearsDesiredStateAndReturnsPending() {
        when(audit.recordBan(anyString(), anyString(), eq("access.restore"), anyString(), anyString(),
                any(), any(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new ModActionRepository.RecordedBan(row("access.restore"), true)));
        when(suspensions.clear(eq("ROLE_MATRIX"), eq("alice"))).thenReturn(Mono.just(SuspensionOutcome.PENDING));
        StepVerifier.create(service.lift("matrix", "alice", null, auth("mod:bob", "ROLE_MOD")))
                .assertNext(r -> assertThat(r.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();
        verify(suspensions).clear("ROLE_MATRIX", "alice");
    }

    // ── DOMAIN-LOCK: below-them guard (mod-domainlocks-admin → 403) ─────
    @Test
    void modDomainLocksAdmin_isForbidden() {
        when(roles.isPrivileged(eq("anadmin"), any())).thenReturn(Mono.just(true));
        StepVerifier.create(service.domainLock(
                        "ROLE_MATRIX_DOMAINLOCKED", "anadmin", null, null, auth("mod:bob", "ROLE_MOD")))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status().value()).isEqualTo(403);
                })
                .verify();
        // No desired-state write happened for a forbidden domain-lock.
        verify(domainLocks, never()).lock(anyString(), anyString(), any());
    }

    // ── mod-domainlocks-mod → 403 (same below-them guard) ──────────────
    @Test
    void modDomainLocksMod_isForbidden() {
        when(roles.isPrivileged(eq("amod"), any())).thenReturn(Mono.just(true));
        StepVerifier.create(service.domainLock(
                        "ROLE_MASTODON_DOMAINLOCKED", "amod", null, null, auth("mod:bob", "ROLE_MOD")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(domainLocks, never()).lock(anyString(), anyString(), any());
    }

    // ── self domain-lock → 403 (before any Casdoor lookup) ─────────────
    @Test
    void selfDomainLock_isForbidden() {
        StepVerifier.create(service.domainLock(
                        "ROLE_MATRIX_DOMAINLOCKED", "mod:bob", null, null, auth("mod:bob", "ROLE_MOD")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(domainLocks, never()).lock(anyString(), anyString(), any());
        // Self-lock is rejected BEFORE the privileged-role lookup is even needed.
        verify(roles, never()).isPrivileged(anyString(), any());
    }

    // ── happy path → pending-reconcile + role→platform map + desired-state ─
    @Test
    void domainLock_writesDesiredStateAndReturnsPending() {
        when(audit.recordBan(anyString(), anyString(), eq("domain.lock"), eq("domain-lock"), anyString(),
                any(), any(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new ModActionRepository.RecordedBan(row("domain.lock"), true)));
        StepVerifier.create(service.domainLock(
                        "ROLE_MASTODON_DOMAINLOCKED", "alice", "abuse", null, auth("mod:bob", "ROLE_MOD")))
                .assertNext(r -> {
                    assertThat(r.state()).isEqualTo("pending-reconcile");
                    assertThat(r.deduped()).isFalse();
                })
                .verifyComplete();
        // ROLE_MASTODON_DOMAINLOCKED → 'mastodon' platform desired-state write with the reason.
        verify(domainLocks).lock(eq("mastodon"), eq("alice"), eq("abuse"));
    }

    // ── breaker-open / degraded admin-bff → still pending (never success) ──
    @Test
    void domainLock_whenAdminBffDegraded_stillPendingAndAudited() {
        when(audit.recordBan(anyString(), anyString(), eq("domain.lock"), eq("domain-lock"), anyString(),
                any(), any(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new ModActionRepository.RecordedBan(row("domain.lock"), true)));
        when(domainLocks.lock(eq("matrix"), eq("alice"), any()))
                .thenReturn(Mono.just(SuspensionOutcome.degraded("CallNotPermittedException")));
        StepVerifier.create(service.domainLock(
                        "ROLE_MATRIX_DOMAINLOCKED", "alice", null, null, auth("mod:bob", "ROLE_MOD")))
                .assertNext(r -> assertThat(r.state()).startsWith("degraded:"))
                .verifyComplete();
        // The local audit row was written even though admin-bff was degraded, stamped
        // with the actor's domain (no DOMAIN_ authority on this auth → "default").
        verify(audit).recordBan(anyString(), anyString(), eq("domain.lock"), eq("domain-lock"),
                eq("alice"), isNull(), eq("user"), isNull(), eq("pending"), eq("default"));
    }

    // ── dedup: a redelivery does NOT re-issue the desired-state write ──
    @Test
    void domainLock_dedupRetry_doesNotReissueDesiredState() {
        when(audit.recordBan(anyString(), anyString(), eq("domain.lock"), eq("domain-lock"), anyString(),
                any(), any(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new ModActionRepository.RecordedBan(row("domain.lock"), false)));
        StepVerifier.create(service.domainLock(
                        "ROLE_MATRIX_DOMAINLOCKED", "alice", null, "idem-1", auth("mod:bob", "ROLE_MOD")))
                .assertNext(r -> {
                    assertThat(r.deduped()).isTrue();
                    assertThat(r.state()).isEqualTo("pending-reconcile");
                })
                .verifyComplete();
        verify(domainLocks, never()).lock(anyString(), anyString(), any());
    }

    // ── unlock → pending + clears desired-state + role→platform map ────
    @Test
    void domainUnlock_clearsDesiredStateAndReturnsPending() {
        when(audit.recordBan(anyString(), anyString(), eq("domain.unlock"), eq("domain-lock"), anyString(),
                any(), any(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new ModActionRepository.RecordedBan(row("domain.unlock"), true)));
        StepVerifier.create(service.domainUnlock(
                        "ROLE_MATRIX_DOMAINLOCKED", "alice", null, auth("mod:bob", "ROLE_MOD")))
                .assertNext(r -> assertThat(r.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();
        verify(domainLocks).unlock("matrix", "alice");
    }

    // ── unlock honours the below-them guard too (mod-unlocks-admin → 403) ─
    @Test
    void modDomainUnlocksAdmin_isForbidden() {
        when(roles.isPrivileged(eq("anadmin"), any())).thenReturn(Mono.just(true));
        StepVerifier.create(service.domainUnlock(
                        "ROLE_MASTODON_DOMAINLOCKED", "anadmin", null, auth("mod:bob", "ROLE_MOD")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(domainLocks, never()).unlock(anyString(), anyString());
    }

    // ── role→platform mapper (defence-in-depth for the {role} path var) ─
    @Test
    void platformForDomainLockRole_mapsBothRoles() {
        assertThat(ModService.platformForDomainLockRole("ROLE_MATRIX_DOMAINLOCKED")).isEqualTo("matrix");
        assertThat(ModService.platformForDomainLockRole("ROLE_MASTODON_DOMAINLOCKED")).isEqualTo("mastodon");
    }

    @Test
    void platformForDomainLockRole_unknownRole_throws400() {
        assertThatThrownBy(() -> ModService.platformForDomainLockRole("ROLE_BOGUS"))
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(400));
    }

    // ── DOMAIN STAMP (CROSS-USER positive cross-effect) ────────────────
    // A ban/lock WRITE stamps the audit row with the actor's OWN issuer-derived domain
    // (the DOMAIN_<x> authority), so the row is partitioned to that brand. A different
    // brand's principal stamps a different domain — the write-side half of the isolation
    // boundary the domain-scoped reads enforce.

    @Test
    void ban_stampsAuditRowWithActorsDomain_brandx() {
        StepVerifier.create(service.ban("matrix", "alice", null, null, null,
                        auth("mod:x", "ROLE_MOD", "DOMAIN_brandx")))
                .assertNext(r -> assertThat(r.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();
        verify(audit).recordBan(anyString(), eq("mod:x"), eq("access.suspend"), eq("access"),
                eq("alice"), any(), eq("user"), any(), eq("pending"), eq("brandx"));
    }

    @Test
    void ban_byDifferentBrand_stampsThatBrandsDomain_brandy() {
        StepVerifier.create(service.ban("mastodon", "carol", null, null, null,
                        auth("mod:y", "ROLE_MOD", "DOMAIN_brandy")))
                .assertNext(r -> assertThat(r.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();
        verify(audit).recordBan(anyString(), eq("mod:y"), eq("access.suspend"), eq("access"),
                eq("carol"), any(), eq("user"), any(), eq("pending"), eq("brandy"));
    }

    @Test
    void domainLock_stampsAuditRowWithActorsDomain() {
        when(audit.recordBan(anyString(), anyString(), eq("domain.lock"), eq("domain-lock"), anyString(),
                any(), any(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new ModActionRepository.RecordedBan(row("domain.lock"), true)));
        StepVerifier.create(service.domainLock("ROLE_MATRIX_DOMAINLOCKED", "alice", null, null,
                        auth("mod:x", "ROLE_MOD", "DOMAIN_brandx")))
                .assertNext(r -> assertThat(r.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();
        verify(audit).recordBan(anyString(), eq("mod:x"), eq("domain.lock"), eq("domain-lock"),
                eq("alice"), any(), eq("user"), any(), eq("pending"), eq("brandx"));
    }

    // ── CROSS-USER: cross-tenant dedup-collision is closed (the gap this fixes) ──
    // Two brands' Casdoor mint the SAME actor-subject string ("alice"), each bans the
    // SAME target+role with NO client idempotencyKey. The dedup key now carries the
    // domain, so the two calls produce DISTINCT keys → brand-Y's recordBan is its OWN
    // fresh row (not a dedup hit against brand-X) and brand-Y's suspend IS invoked
    // (never silently swallowed), with NO brand-X data in brand-Y's flow.
    @Test
    void crossTenantSameActorSubject_brandYIsFreshAndSuspendInvoked() {
        // Capture the dedup key each brand computes; assert they DIFFER (domain-scoped).
        org.mockito.ArgumentCaptor<String> keyCap = org.mockito.ArgumentCaptor.forClass(String.class);

        // Brand-X bans (actor subject "alice") → fresh row stamped brandx.
        StepVerifier.create(service.ban("matrix", "victim", null, null, null,
                        auth("alice", "ROLE_MOD", "DOMAIN_brandx")))
                .assertNext(r -> assertThat(r.deduped()).isFalse())
                .verifyComplete();

        // Brand-Y bans with the SAME actor subject "alice", same target+role, no idem key.
        StepVerifier.create(service.ban("matrix", "victim", null, null, null,
                        auth("alice", "ROLE_MOD", "DOMAIN_brandy")))
                .assertNext(r -> {
                    assertThat(r.deduped()).as("brand-Y is NOT deduped against brand-X").isFalse();
                    assertThat(r.state()).isEqualTo("pending-reconcile");
                })
                .verifyComplete();

        // Both brands' suspends were invoked (brand-Y's effect was NOT swallowed).
        verify(suspensions, org.mockito.Mockito.times(2)).suspend(eq("ROLE_MATRIX"), eq("victim"), any(), any());
        // The two recordBan calls used DIFFERENT dedup keys (domain in the key) and the
        // correct per-brand domain stamp.
        verify(audit).recordBan(keyCap.capture(), eq("alice"), eq("access.suspend"), eq("access"),
                eq("victim"), any(), eq("user"), any(), eq("pending"), eq("brandx"));
        verify(audit).recordBan(keyCap.capture(), eq("alice"), eq("access.suspend"), eq("access"),
                eq("victim"), any(), eq("user"), any(), eq("pending"), eq("brandy"));
        assertThat(keyCap.getAllValues().get(0))
                .as("brand-X and brand-Y dedup keys must DIFFER (domain folded into the key)")
                .isNotEqualTo(keyCap.getAllValues().get(1));
    }

    @Test
    void ban_ambiguousDomainAuthorities_failClosedToDefaultStamp() {
        // Two DOMAIN_ authorities (injection signature) -> Roles.domainOf == null ->
        // the WRITE defensively stamps "default" (never another brand, never un-scoped).
        StepVerifier.create(service.ban("matrix", "alice", null, null, null,
                        auth("mod:x", "ROLE_MOD", "DOMAIN_brandx", "DOMAIN_brandy")))
                .assertNext(r -> assertThat(r.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();
        verify(audit).recordBan(anyString(), eq("mod:x"), eq("access.suspend"), eq("access"),
                eq("alice"), any(), eq("user"), any(), eq("pending"), eq("default"));
    }

    // ════════════════════════════════════════════════════════════════════
    //  CROSS-USER / CROSS-TENANT — the A01 BOLA/BFLA fix (CWE-639)
    //  A brand-X MOD may NOT ban / domain-lock / lift a target that does NOT
    //  belong to brand-X's tenant. The target's brand is resolved
    //  AUTHORITATIVELY against the caller's per-domain Casdoor org
    //  (CasdoorRoleClient.belongsToDomain); a non-member is DENIED (403)
    //  fail-closed BEFORE any suspend()/lock()/clear() write is assembled.
    //  SUPERADMIN (cross-domain infra control plane) is the legitimate bypass.
    // ════════════════════════════════════════════════════════════════════

    // ── DENY: brand-X mod bans a brand-Y target → 403, NO write, NO audit row ──
    @Test
    void ban_crossTenantTarget_isForbidden_andNoWriteAssembled() {
        // brand-X caller; Casdoor cannot prove the target lives in brand-X's org.
        when(roles.belongsToDomain(eq("victim-of-brandy"), eq("brandx")))
                .thenReturn(Mono.just(false));
        StepVerifier.create(service.ban("matrix", "victim-of-brandy", null, null, null,
                        auth("mod:x", "ROLE_MOD", "DOMAIN_brandx")))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status().value()).isEqualTo(403);
                })
                .verify();
        // FAIL-CLOSED: the deny short-circuits BEFORE the privileged read, the dedup
        // row, and the desired-state write — none of them run on a cross-tenant target.
        verify(roles, never()).isPrivileged(anyString(), any());
        verify(audit, never()).recordBan(anyString(), anyString(), anyString(), anyString(),
                anyString(), any(), any(), any(), anyString(), anyString());
        verify(suspensions, never()).suspend(anyString(), anyString(), any(), any());
    }

    // ── DENY: brand-X mod domain-locks a brand-Y target → 403, NO lock write ──
    @Test
    void domainLock_crossTenantTarget_isForbidden_andNoLockAssembled() {
        when(roles.belongsToDomain(eq("victim-of-brandy"), eq("brandx")))
                .thenReturn(Mono.just(false));
        StepVerifier.create(service.domainLock("ROLE_MATRIX_DOMAINLOCKED", "victim-of-brandy",
                        null, null, auth("mod:x", "ROLE_MOD", "DOMAIN_brandx")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(domainLocks, never()).lock(anyString(), anyString(), any());
        verify(audit, never()).recordBan(anyString(), anyString(), anyString(), anyString(),
                anyString(), any(), any(), any(), anyString(), anyString());
    }

    // ── DENY: brand-X mod lifts a brand-Y target's ban → 403, NO clear write ──
    @Test
    void lift_crossTenantTarget_isForbidden_andNoClearAssembled() {
        when(roles.belongsToDomain(eq("victim-of-brandy"), eq("brandx")))
                .thenReturn(Mono.just(false));
        StepVerifier.create(service.lift("matrix", "victim-of-brandy", null,
                        auth("mod:x", "ROLE_MOD", "DOMAIN_brandx")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(suspensions, never()).clear(anyString(), anyString());
        verify(audit, never()).recordBan(anyString(), anyString(), anyString(), anyString(),
                anyString(), any(), any(), any(), anyString(), anyString());
    }

    // ════════════════════════════════════════════════════════════════════
    //  BUG-A — the server-wide BLOCK surface now runs the SAME below-them /
    //  cross-tenant guards as ban(): guardNotSelf → guardSameTenant →
    //  guardNotPrivileged, ALL before assertPlatformRole and before any
    //  external homeserver call or audit row. (block() previously SKIPPED
    //  these guards.) These mirror ban_crossTenantTarget/self/privileged.
    //  FAIL-FIRST: against the unfixed inline block() they would NOT hold —
    //  the external call + audit row ran for a cross-tenant/privileged/self
    //  target.
    // ════════════════════════════════════════════════════════════════════

    // ── DENY: brand-X mod blocks a brand-Y target → 403, NO external, NO audit ──
    @Test
    void block_crossTenantTarget_isForbidden_andNoEffect() {
        when(roles.belongsToDomain(eq("victim-of-brandy"), eq("brandx")))
                .thenReturn(Mono.just(false));
        StepVerifier.create(service.block("matrix", "user", "victim-of-brandy", "abuse",
                        auth("mod:x", "ROLE_MOD", "ROLE_MATRIX", "DOMAIN_brandx")))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status().value()).isEqualTo(403);
                })
                .verify();
        // FAIL-CLOSED: the deny short-circuits BEFORE the privileged read, the external
        // homeserver call, and the audit row.
        verify(roles, never()).isPrivileged(anyString(), any());
        verify(matrix, never()).blockUser(anyString());
        verify(matrix, never()).blockInstance(anyString());
        verify(audit, never()).record(anyString(), anyString(), anyString(), anyString(),
                any(), anyString(), anyString());
    }

    // ── DENY: a mod may not block THEMSELVES → 403, before any Casdoor/effect ──
    @Test
    void block_self_isForbidden_andNoEffect() {
        StepVerifier.create(service.block("matrix", "user", "mod:bob", null,
                        auth("mod:bob", "ROLE_MOD", "ROLE_MATRIX")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        // Self-block is rejected BEFORE the privileged-role lookup is even needed.
        verify(roles, never()).isPrivileged(anyString(), any());
        verify(matrix, never()).blockUser(anyString());
        verify(audit, never()).record(anyString(), anyString(), anyString(), anyString(),
                any(), anyString(), anyString());
    }

    // ── DENY: a mod may not block a PRIVILEGED (ROLE_ADMIN/ROLE_MOD) target → 403 ──
    @Test
    void block_privilegedTarget_isForbidden_andNoEffect() {
        when(roles.isPrivileged(eq("anadmin"), any())).thenReturn(Mono.just(true));
        StepVerifier.create(service.block("mastodon", "user", "anadmin", null,
                        auth("mod:bob", "ROLE_MOD", "ROLE_MASTODON")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        // No external homeserver call and no audit row for a privileged target.
        verify(mastodon, never()).blockUser(anyString());
        verify(audit, never()).record(anyString(), anyString(), anyString(), anyString(),
                any(), anyString(), anyString());
    }

    // ── ALLOW (control): a same-tenant, non-privileged target → block proceeds ──
    @Test
    void block_sameTenantNonPrivileged_isAllowed_andRecordsWithCallersDomain() {
        when(roles.belongsToDomain(eq("@spam:evil"), eq("brandx"))).thenReturn(Mono.just(true));
        StepVerifier.create(service.block("matrix", "user", "@spam:evil", "abuse",
                        auth("mod:x", "ROLE_MOD", "ROLE_MATRIX", "DOMAIN_brandx")))
                .assertNext(r -> assertThat(r.outcome().result()).isEqualTo("stubbed"))
                .verifyComplete();
        verify(matrix).blockUser("@spam:evil");
        // BUG-B mirror: the block row is stamped with the caller's validated brand.
        verify(audit).record(eq("mod:x"), eq("matrix.block-user"), eq("matrix"),
                eq("@spam:evil"), eq("abuse"), eq("stubbed"), eq("brandx"));
    }

    // ── ALLOW (control): brand-X mod bans a PROVEN brand-X target → write proceeds ──
    @Test
    void ban_sameTenantTarget_isAllowed_andWriteProceeds() {
        when(roles.belongsToDomain(eq("alice"), eq("brandx"))).thenReturn(Mono.just(true));
        StepVerifier.create(service.ban("matrix", "alice", null, null, null,
                        auth("mod:x", "ROLE_MOD", "DOMAIN_brandx")))
                .assertNext(r -> assertThat(r.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();
        // The same-tenant target was resolved against the CALLER's brand org, then the
        // write proceeded — the legitimate flow is preserved.
        verify(roles).belongsToDomain(eq("alice"), eq("brandx"));
        verify(suspensions).suspend(eq("ROLE_MATRIX"), eq("alice"), any(), any());
    }

    // ── ALLOW (control): SUPERADMIN bans cross-brand → bypasses the tenant proof ──
    @Test
    void ban_superadminCrossBrand_bypassesTenantGuard_andWriteProceeds() {
        // A SUPERADMIN scoped to brandx bans a target that does NOT resolve in brandx —
        // the infra control plane is UNSCOPED, so the same-tenant guard is bypassed and
        // belongsToDomain is never even consulted.
        StepVerifier.create(service.ban("mastodon", "carol-of-brandy", null, null, null,
                        auth("super:root", "ROLE_SUPERADMIN", "DOMAIN_brandx")))
                .assertNext(r -> assertThat(r.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();
        verify(roles, never()).belongsToDomain(anyString(), any());
        verify(suspensions).suspend(eq("ROLE_MASTODON"), eq("carol-of-brandy"), any(), any());
    }

    // ── single-tenant 'default' caller skips the tenant guard entirely ──
    @Test
    void ban_defaultDomainCaller_skipsTenantGuard() {
        // No DOMAIN_<brand> -> 'default' (single-tenant inert domain): one org, no
        // cross-tenant surface, so belongsToDomain is never consulted and the ban runs.
        StepVerifier.create(service.ban("matrix", "alice", null, null, null,
                        auth("mod:bob", "ROLE_MOD")))
                .assertNext(r -> assertThat(r.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();
        verify(roles, never()).belongsToDomain(anyString(), any());
        verify(suspensions).suspend(eq("ROLE_MATRIX"), eq("alice"), any(), any());
    }

    // ════════════════════════════════════════════════════════════════════
    //  finding-6 — privileged-target guard FAILS CLOSED when the Casdoor seam
    //  is DISABLED (the default casdoor.admin.enabled=false). Wired end-to-end
    //  through ban() with a REAL disabled-seam CasdoorRoleClient (NOT the mock)
    //  so the integrated guardNotPrivileged decision is exercised, not stubbed.
    //  Previously the disabled seam resolved isPrivileged=false for EVERY caller
    //  → a MOD could ban an ADMIN/MOD whenever the seam was left unwired. Now a
    //  BRANDED (multi-tenant/production) caller fails closed (403), while the
    //  single-tenant offline flow still bans ordinary users.
    //  FAIL-FIRST: against the old fail-OPEN disabled branch the branded ban
    //  would have proceeded to a 202 + suspend() — the 403 assertion would fail.
    // ════════════════════════════════════════════════════════════════════

    /** A ModService whose privileged-target lookups use a REAL CasdoorRoleClient with the
     *  seam DISABLED (no Casdoor creds — the default posture). The same-tenant guard is the
     *  mock (already covered above), so this isolates the privileged-target disabled-seam
     *  decision. The no-op WebClient is never called because the disabled seam short-circuits
     *  before any HTTP. */
    private ModService serviceWithRealDisabledSeam() {
        CasdoorRoleClient realDisabled = new CasdoorRoleClient(
                org.springframework.web.reactive.function.client.WebClient.builder()
                        .baseUrl("http://casdoor.invalid").build(),
                "hugmesh", false, java.util.Map.of());
        return new ModService(suspensions, domainLocks, realDisabled, audit, matrix, mastodon, owncast);
    }

    // ── EXPLOIT REJECTED: branded MOD bans an admin, seam off → 403, NO write ──
    @Test
    void ban_seamDisabled_brandedCaller_privilegedTargetGuardFailsClosed() {
        ModService svc = serviceWithRealDisabledSeam();
        StepVerifier.create(svc.ban("matrix", "anadmin", null, null, null,
                        auth("mod:x", "ROLE_MOD", "DOMAIN_brandx")))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status().value()).isEqualTo(403);
                })
                .verify();
        // FAIL-CLOSED: no desired-state write for a (now-treated-as-privileged) target.
        verify(suspensions, never()).suspend(anyString(), anyString(), any(), any());
    }

    // ── EXPLOIT REJECTED (domain-lock variant): branded MOD locks an admin, seam off → 403 ──
    @Test
    void domainLock_seamDisabled_brandedCaller_privilegedTargetGuardFailsClosed() {
        ModService svc = serviceWithRealDisabledSeam();
        StepVerifier.create(svc.domainLock("ROLE_MATRIX_DOMAINLOCKED", "anadmin", null, null,
                        auth("mod:x", "ROLE_MOD", "DOMAIN_brandx")))
                .expectErrorSatisfies(e -> assertThat(((ApiException) e).status().value()).isEqualTo(403))
                .verify();
        verify(domainLocks, never()).lock(anyString(), anyString(), any());
    }

    // ── LEGIT STILL WORKS: single-tenant ('default') MOD bans, seam off → ban proceeds ──
    @Test
    void ban_seamDisabled_singleTenantCaller_stillProceeds() {
        ModService svc = serviceWithRealDisabledSeam();
        // No DOMAIN_<brand> -> 'default' single-tenant inert domain: the disabled seam keeps
        // the permissive default so the offline dev/CI + single-org flow still bans users.
        StepVerifier.create(svc.ban("matrix", "alice", null, null, null,
                        auth("mod:bob", "ROLE_MOD")))
                .assertNext(r -> assertThat(r.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();
        verify(suspensions).suspend(eq("ROLE_MATRIX"), eq("alice"), any(), any());
    }
}
