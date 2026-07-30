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

import java.time.LocalDateTime;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Notifications PR6 — the service-scoped {@code @system} notification DIRECTIVE on a ban.
 *
 * <ul>
 *   <li>SERVICE-SCOPING — a matrix ban's matrix channel is forwarded; an off-scope
 *       mastodon channel is DROPPED before forwarding/persistence.</li>
 *   <li>PERSISTED — the resolved directive is stamped on the mod_action row (the 12-arg
 *       recordBan).</li>
 *   <li>FORWARDED — the directive rides the admin-bff suspend write.</li>
 *   <li>EMAIL-ONLY — notify_email_only forces email+in-app and is forwarded as emailOnly.</li>
 *   <li><b>NO-MOD-IDENTITY-IN-PAYLOAD</b> — neither the persisted directive nor the
 *       forwarded write carries the acting moderator's identity. The actor appears ONLY in
 *       the audit row's own {@code actor} column (the local trail), NEVER in any field that
 *       feeds the neutral @system notification (channels/email-only/reason/ttl/target).</li>
 * </ul>
 */
class ModServiceNotifyTest {

    AdminSuspensionClient suspensions;
    AdminDomainLockClient domainLocks;
    CasdoorRoleClient roles;
    ModActionRepository audit;
    ModService service;

    private static Authentication auth(String name, String... authorities) {
        return new UsernamePasswordAuthenticationToken(
                name, "n/a", AuthorityUtils.createAuthorityList(authorities));
    }

    private static ModAction row() {
        return new ModAction("id-1", "mod:bob", "access.suspend", "access", "alice", "abuse",
                "pending", LocalDateTime.parse("2026-06-06T00:00:00"), "k", "user", null, "pending");
    }

    @BeforeEach
    void setUp() {
        suspensions = mock(AdminSuspensionClient.class);
        domainLocks = mock(AdminDomainLockClient.class);
        roles = mock(CasdoorRoleClient.class);
        audit = mock(ModActionRepository.class);
        service = new ModService(suspensions, domainLocks, roles, audit,
                mock(systems.hugmesh.modbff.external.MatrixAdminClient.class),
                mock(systems.hugmesh.modbff.external.MastodonAdminClient.class),
                mock(systems.hugmesh.modbff.owncast.OwncastModClient.class));
        when(roles.isPrivileged(anyString(), any())).thenReturn(Mono.just(false));
        when(roles.belongsToDomain(anyString(), any())).thenReturn(Mono.just(true));
        // 12-arg (directive-aware) recordBan
        when(audit.recordBan(anyString(), anyString(), anyString(), anyString(), anyString(),
                any(), any(), any(), anyString(), anyString(), any(), any()))
                .thenReturn(Mono.just(new ModActionRepository.RecordedBan(row(), true)));
        // 6-arg (directive-aware) suspend
        when(suspensions.suspend(anyString(), anyString(), any(), any(), any(), anyBoolean()))
                .thenReturn(Mono.just(SuspensionOutcome.PENDING));
    }

    // ── SERVICE-SCOPING + PERSISTED + FORWARDED ──────────────────────────────
    @Test
    void ban_withMatrixDirective_scopesPersistsAndForwards() {
        AtomicReference<List<String>> forwarded = new AtomicReference<>();
        when(suspensions.suspend(eq("ROLE_MATRIX"), eq("alice"), any(), any(), any(), anyBoolean()))
                .thenAnswer(inv -> {
                    forwarded.set(inv.getArgument(4));
                    return Mono.just(SuspensionOutcome.PENDING);
                });

        // A matrix ban requesting in-app + matrix + (off-scope) mastodon.
        StepVerifier.create(service.ban("matrix", "alice", 3600L, "abuse", null,
                        List.of("in-app", "matrix", "mastodon"), false, auth("mod:bob", "ROLE_MOD")))
                .assertNext(r -> assertThat(r.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();

        // FORWARDED directive is service-scoped: mastodon dropped.
        assertThat(forwarded.get()).containsExactly("in-app", "matrix");
        // PERSISTED CSV on the row is the same scoped set; emailOnly null.
        verify(audit).recordBan(anyString(), anyString(), eq("access.suspend"), eq("access"),
                eq("alice"), eq("abuse"), eq("user"), any(), eq("pending"), anyString(),
                eq("in-app,matrix"), eq(null));
    }

    // ── EMAIL-ONLY forces email+in-app ───────────────────────────────────────
    @Test
    void ban_emailOnly_forcesEmailAndInApp_andForwardsEmailOnly() {
        AtomicReference<List<String>> forwarded = new AtomicReference<>();
        AtomicReference<Boolean> emailOnlyFwd = new AtomicReference<>();
        when(suspensions.suspend(eq("ROLE_MATRIX"), eq("alice"), any(), any(), any(), anyBoolean()))
                .thenAnswer(inv -> {
                    forwarded.set(inv.getArgument(4));
                    emailOnlyFwd.set(inv.getArgument(5));
                    return Mono.just(SuspensionOutcome.PENDING);
                });

        StepVerifier.create(service.ban("matrix", "alice", null, null, null,
                        List.of("matrix"), true, auth("mod:bob", "ROLE_MOD")))
                .assertNext(r -> assertThat(r.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();

        assertThat(forwarded.get()).containsExactlyInAnyOrder("in-app", "email");
        assertThat(emailOnlyFwd.get()).isTrue();
        verify(audit).recordBan(anyString(), anyString(), anyString(), anyString(), anyString(),
                any(), any(), any(), anyString(), anyString(), anyString(), eq(Boolean.TRUE));
    }

    // ── NO-MOD-IDENTITY-IN-PAYLOAD (the dedicated guard) ─────────────────────
    @Test
    void ban_neverForwardsNorPersistsTheModIdentityIntoTheNotificationPayload() {
        // Capture EVERY argument forwarded to admin-bff's suspend write.
        AtomicReference<Object[]> fwd = new AtomicReference<>();
        when(suspensions.suspend(eq("ROLE_MATRIX"), eq("alice"), any(), any(), any(), anyBoolean()))
                .thenAnswer(inv -> {
                    fwd.set(inv.getArguments());
                    return Mono.just(SuspensionOutcome.PENDING);
                });
        // Capture EVERY argument persisted via the directive-aware recordBan.
        AtomicReference<Object[]> rec = new AtomicReference<>();
        when(audit.recordBan(anyString(), anyString(), anyString(), anyString(), anyString(),
                any(), any(), any(), anyString(), anyString(), any(), any()))
                .thenAnswer(inv -> {
                    rec.set(inv.getArguments());
                    return Mono.just(new ModActionRepository.RecordedBan(row(), true));
                });

        String actor = "mod:bob-the-moderator";
        StepVerifier.create(service.ban("matrix", "alice", 3600L, "abuse", null,
                        List.of("matrix"), false, auth(actor, "ROLE_MOD")))
                .assertNext(r -> assertThat(r.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();

        // The FORWARDED write (role, user, ttl, reason, channels, emailOnly) — NONE of the
        // notification-feeding fields contain the actor. role/user/reason are the target's
        // context; channels are 'matrix'; the actor string appears NOWHERE.
        for (Object arg : fwd.get()) {
            assertThat(String.valueOf(arg)).doesNotContain(actor);
        }
        // The PERSISTED directive fields (notify_channels CSV @ idx 10, emailOnly @ idx 11)
        // carry no actor either. (The audit row's OWN actor column — recordBan arg idx 1 —
        // is the local trail and is expected to equal the actor; that is NOT the @system
        // notification payload.)
        Object[] r = rec.get();
        assertThat(String.valueOf(r[1])).as("the audit row's actor column IS the actor").isEqualTo(actor);
        assertThat(String.valueOf(r[10])).as("notify_channels CSV has no actor").doesNotContain(actor);
        assertThat(String.valueOf(r[11])).as("notify_email_only has no actor").doesNotContain(actor);
        // And the suspend write was the directive-aware overload (notification rides it),
        // not the legacy directive-less one.
        verify(suspensions).suspend(eq("ROLE_MATRIX"), eq("alice"), eq(3600L), eq("abuse"),
                any(), anyBoolean());
        verify(suspensions, never()).suspend(anyString(), anyString(), any(), any());
    }

    // ── NO DIRECTIVE → legacy directive-less write + row (back-compat) ───────
    @Test
    void ban_noDirective_usesLegacyDirectivelessWrite() {
        when(suspensions.suspend(anyString(), anyString(), any(), any()))
                .thenReturn(Mono.just(SuspensionOutcome.PENDING));
        when(audit.recordBan(anyString(), anyString(), anyString(), anyString(), anyString(),
                any(), any(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new ModActionRepository.RecordedBan(row(), true)));

        StepVerifier.create(service.ban("matrix", "alice", null, null, null,
                        List.of(), false, auth("mod:bob", "ROLE_MOD")))
                .assertNext(r -> assertThat(r.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();

        // No-directive path uses the legacy overloads (wire body + row unchanged).
        verify(suspensions).suspend(eq("ROLE_MATRIX"), eq("alice"), any(), any());
        verify(suspensions, never()).suspend(anyString(), anyString(), any(), any(), any(), anyBoolean());
    }
}
