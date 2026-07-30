package systems.hugmesh.modbff;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.modbff.admin.AdminDomainLockClient;
import systems.hugmesh.modbff.admin.AdminSuspensionClient;
import systems.hugmesh.modbff.admin.CasdoorRoleClient;
import systems.hugmesh.modbff.admin.SuspensionOutcome;
import systems.hugmesh.modbff.audit.ModAction;
import systems.hugmesh.modbff.audit.ModActionRepository;
import systems.hugmesh.modbff.audit.ModActionType;
import systems.hugmesh.modbff.config.SecurityConfig;
import systems.hugmesh.modbff.external.MastodonAdminClient;
import systems.hugmesh.modbff.external.MatrixAdminClient;
import systems.hugmesh.modbff.federation.FederationApiClient;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.modbff.service.ModService;
import systems.hugmesh.modbff.web.ApiExceptionHandler;
import systems.hugmesh.modbff.web.ValidationExceptionHandler;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * WAVE-2c GAP CLOSURE — the controller-layer seam-ON cross-domain DENY for the three
 * endpoints wave-2 left service-only: {@code lift} (DELETE {@code /bff/mod/ban}),
 * {@code domainLock} (POST {@code /bff/mod/domain-lock/{role}/{user}}), and
 * {@code domainUnlock} (DELETE {@code /bff/mod/domain-lock/{role}/{user}}). All three
 * share {@link ModService#guardSameTenant} with {@code ban}, but only {@code ban} had a
 * controller-layer seam-ON test ({@link Wave2CasdoorSeamOnControllerTest}); the
 * cross-tenant DENY for these three was proven ONLY at the service layer (in
 * {@code ModServiceTest}) against a MOCKED {@link CasdoorRoleClient}. This slice drives
 * the SAME guard from the HTTP boundary through the REAL prod {@link SecurityConfig}
 * filter chain, the REAL {@link ModController}, the REAL {@link ModService}, and the
 * REAL seam-ON {@link CasdoorRoleClient} against an in-process stub Casdoor — only the
 * leaf effects (admin-bff suspension/domain-lock clients, the audit repo) are mocked.
 *
 * <p>The acting moderator carries a real issuer-derived {@code DOMAIN_brandx} authority,
 * so {@link systems.hugmesh.modbff.security.Roles#domainOf} resolves "brandx" and the
 * branded-caller leg of {@code guardSameTenant} runs the REAL Casdoor
 * {@code GET /api/get-user?id=<org>/<target>} read keyed off the caller's brand org
 * (orgx). For each endpoint:
 *
 * <ul>
 *   <li><b>CROSS-DOMAIN DENY</b> — a target who lives in brand-Y's org (orgy) is ABSENT
 *       when read against brand-X's org → {@code belongsToDomain} false → the same-tenant
 *       guard 403s at the controller BEFORE any admin-bff clear/lock/unlock write and
 *       BEFORE the dedup audit row. The DENY is mutation-resistant: it is asserted at the
 *       HTTP layer (403 {error}) AND paired with {@code verify(client, never())} on the
 *       leaf write + {@code verify(audit, never())} on the dedup row — it would FAIL if
 *       the guard were removed (the write would land + a 202 would return).</li>
 *   <li><b>SAME-TENANT ALLOW (sensitivity sentinel)</b> — the SAME request + SAME caller,
 *       but the target IS registered in the caller's org (orgx) and non-privileged, flips
 *       to 202 pending-reconcile and the leaf write IS called. This pins each DENY's
 *       dependency on the same-tenant guard so a future weakening of cross-brand isolation
 *       (the A01/CWE-639 regression) cannot leave the DENY passing vacuously.</li>
 * </ul>
 *
 * <p>The reads are proven CALLER-org-scoped via {@link CasdoorRecorder#lastGetUserId()}
 * (the recorded outbound get-user id is {@code orgx/<target>}), the fix that makes the
 * cross-tenant deny authoritative.
 */
@WebFluxTest(controllers = ModController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ApiExceptionHandler.class,
        ValidationExceptionHandler.class, Wave2cSeamOnLockLiftControllerTest.SeamOnWiring.class})
class Wave2cSeamOnLockLiftControllerTest {

    @Autowired ApplicationContext context;
    WebTestClient web;

    @BeforeEach
    void buildWebTestClient() {
        // Spring Security 7 (Boot 4): mockJwt()/mock* mutations require a WebTestClient
        // bound to the context WITH springSecurity() applied, else every request is 401.
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    // The real ModService + real (seam-ON) CasdoorRoleClient are supplied by SeamOnWiring;
    // only the leaf effects are mocked.
    @org.springframework.test.context.bean.override.mockito.MockitoBean FederationApiClient federation;
    @org.springframework.test.context.bean.override.mockito.MockitoBean MatrixAdminClient matrix;
    @org.springframework.test.context.bean.override.mockito.MockitoBean MastodonAdminClient mastodon;
    @org.springframework.test.context.bean.override.mockito.MockitoBean ModActionRepository audit;
    @org.springframework.test.context.bean.override.mockito.MockitoBean AdminSuspensionClient suspensions;
    @org.springframework.test.context.bean.override.mockito.MockitoBean AdminDomainLockClient domainLocks;
    @org.springframework.test.context.bean.override.mockito.MockitoBean ReactiveJwtDecoder jwtDecoder;

    /** The shared recorder the stub Casdoor answers from + records outbound requests to. */
    @Autowired CasdoorRecorder casdoor;

    @org.junit.jupiter.api.BeforeEach
    void resetRecorder() {
        casdoor.reset();
    }

    /** A brand-X moderator: ROLE_MOD + the issuer-derived DOMAIN_brandx authority, so the
     *  branded-caller same-tenant guard runs the REAL Casdoor read against brand-X's org. */
    private WebTestClient asBrandXMod() {
        return web.mutateWith(mockJwt().jwt(j -> j.subject("mod:bob")).authorities(
                new SimpleGrantedAuthority("ROLE_USER"),
                new SimpleGrantedAuthority("ROLE_MOD"),
                new SimpleGrantedAuthority("DOMAIN_brandx")));
    }

    /** Make the dedup audit-row write succeed (fresh pending) so an ALLOW reaches the leaf
     *  write. The same-tenant guard runs BEFORE this, so a DENY never reaches it. */
    private void stubAuditRecord(String action) {
        ModAction row = new ModAction("b-1", "mod:bob", action, "access", "victim",
                null, "pending", LocalDateTime.parse("2026-06-06T00:00:00"),
                "dk", "user", null, "pending", "brandx", null, null);
        when(audit.recordBan(anyString(), anyString(), eq(action), anyString(), anyString(),
                any(), anyString(), any(), anyString(), eq("brandx")))
                .thenReturn(Mono.just(new ModActionRepository.RecordedBan(row, true)));
    }

    /** No privileged-role membership in orgx, so the privileged-target guard passes on the
     *  ALLOW path (domainLock/domainUnlock run guardNotPrivileged; lift does not). */
    private void noPrivilegedMembers() {
        casdoor.roleMembers("orgx/ROLE_ADMIN", List.of());
        casdoor.roleMembers("orgx/ROLE_MOD", List.of());
    }

    // ════════════════════════════════════════════════════════════════════
    //  LIFT — DELETE /bff/mod/ban  (clears access_suspension desired-state)
    // ════════════════════════════════════════════════════════════════════

    // ── CROSS-DOMAIN DENY: a brand-Y target read against brand-X's org is ABSENT ──
    @Test
    void lift_crossDomainTarget_isDenied403_noAdminBffClear() {
        // The stub only knows brand-Y's org (orgy) members; keyed off brand-X's org (orgx)
        // the get-user for orgx/victim returns data:null → belongsToDomain false → 403.
        casdoor.knownUser("orgy/victim");
        asBrandXMod().method(HttpMethod.DELETE).uri("/bff/mod/ban")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"victim\"}")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error")
                .isEqualTo("target is not in the moderator's domain and cannot be moderated cross-tenant");
        // DENY assertion (mutation-resistant): the cross-tenant lift NEVER reached the
        // admin-bff clear() write nor the audit dedup row — the guard short-circuited first.
        verify(suspensions, never()).clear(anyString(), anyString());
        verify(audit, never()).recordBan(anyString(), anyString(), anyString(), anyString(),
                anyString(), any(), anyString(), any(), anyString(), anyString());
        // SEAM-ON proof: the tenant read was keyed off the CALLER's brand org (orgx).
        assertThat(casdoor.lastGetUserId()).isEqualTo("orgx/victim");
    }

    // ── SAME-TENANT ALLOW (sensitivity sentinel) — same request, victim in orgx → 202 ──
    @Test
    void lift_sameTenantTarget_proceeds202_provingDenyIsLoadBearing() {
        casdoor.knownUser("orgx/victim");
        stubAuditRecord(ModActionType.ACCESS_RESTORE);
        when(suspensions.clear(eq("ROLE_MATRIX"), eq("victim")))
                .thenReturn(Mono.just(SuspensionOutcome.PENDING));
        asBrandXMod().method(HttpMethod.DELETE).uri("/bff/mod/ban")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"victim\"}")
                .exchange()
                .expectStatus().isAccepted()
                .expectBody()
                .jsonPath("$.state").isEqualTo("pending-reconcile")
                .jsonPath("$.action.action").isEqualTo("access.restore");
        verify(suspensions).clear(eq("ROLE_MATRIX"), eq("victim"));
        // Read still keyed off orgx — same id as the deny test, opposite result.
        assertThat(casdoor.lastGetUserId()).isEqualTo("orgx/victim");
    }

    // ════════════════════════════════════════════════════════════════════
    //  DOMAIN-LOCK — POST /bff/mod/domain-lock/{role}/{user}
    // ════════════════════════════════════════════════════════════════════

    // ── CROSS-DOMAIN DENY ──
    @Test
    void domainLock_crossDomainTarget_isDenied403_noAdminBffLock() {
        casdoor.knownUser("orgy/victim");
        asBrandXMod().post()
                .uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/victim")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"abuse\"}")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error")
                .isEqualTo("target is not in the moderator's domain and cannot be moderated cross-tenant");
        // DENY assertion (mutation-resistant): no admin-bff lock() write, no dedup row.
        verify(domainLocks, never()).lock(anyString(), anyString(), any());
        verify(audit, never()).recordBan(anyString(), anyString(), anyString(), anyString(),
                anyString(), any(), anyString(), any(), anyString(), anyString());
        assertThat(casdoor.lastGetUserId()).isEqualTo("orgx/victim");
    }

    // ── SAME-TENANT ALLOW (sensitivity sentinel) ──
    @Test
    void domainLock_sameTenantTarget_proceeds202_provingDenyIsLoadBearing() {
        casdoor.knownUser("orgx/victim");
        noPrivilegedMembers();   // domainLock also runs guardNotPrivileged
        stubAuditRecord(ModActionType.DOMAIN_LOCK);
        when(domainLocks.lock(eq("matrix"), eq("victim"), any()))
                .thenReturn(Mono.just(SuspensionOutcome.PENDING));
        asBrandXMod().post()
                .uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/victim")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"abuse\"}")
                .exchange()
                .expectStatus().isAccepted()
                .expectBody()
                .jsonPath("$.state").isEqualTo("pending-reconcile")
                .jsonPath("$.action.action").isEqualTo("domain.lock");
        verify(domainLocks).lock(eq("matrix"), eq("victim"), any());
        assertThat(casdoor.lastGetUserId()).isEqualTo("orgx/victim");
    }

    // ════════════════════════════════════════════════════════════════════
    //  DOMAIN-UNLOCK — DELETE /bff/mod/domain-lock/{role}/{user}
    // ════════════════════════════════════════════════════════════════════

    // ── CROSS-DOMAIN DENY ──
    @Test
    void domainUnlock_crossDomainTarget_isDenied403_noAdminBffUnlock() {
        casdoor.knownUser("orgy/victim");
        asBrandXMod().method(HttpMethod.DELETE)
                .uri("/bff/mod/domain-lock/ROLE_MASTODON_DOMAINLOCKED/victim")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error")
                .isEqualTo("target is not in the moderator's domain and cannot be moderated cross-tenant");
        // DENY assertion (mutation-resistant): no admin-bff unlock() write, no dedup row.
        verify(domainLocks, never()).unlock(anyString(), anyString());
        verify(audit, never()).recordBan(anyString(), anyString(), anyString(), anyString(),
                anyString(), any(), anyString(), any(), anyString(), anyString());
        assertThat(casdoor.lastGetUserId()).isEqualTo("orgx/victim");
    }

    // ── SAME-TENANT ALLOW (sensitivity sentinel) ──
    @Test
    void domainUnlock_sameTenantTarget_proceeds202_provingDenyIsLoadBearing() {
        casdoor.knownUser("orgx/victim");
        noPrivilegedMembers();   // domainUnlock also runs guardNotPrivileged
        stubAuditRecord(ModActionType.DOMAIN_UNLOCK);
        when(domainLocks.unlock(eq("mastodon"), eq("victim")))
                .thenReturn(Mono.just(SuspensionOutcome.PENDING));
        asBrandXMod().method(HttpMethod.DELETE)
                .uri("/bff/mod/domain-lock/ROLE_MASTODON_DOMAINLOCKED/victim")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isAccepted()
                .expectBody()
                .jsonPath("$.state").isEqualTo("pending-reconcile")
                .jsonPath("$.action.action").isEqualTo("domain.unlock");
        verify(domainLocks).unlock(eq("mastodon"), eq("victim"));
        assertThat(casdoor.lastGetUserId()).isEqualTo("orgx/victim");
    }

    // ── SELF short-circuits BEFORE any Casdoor read (domainLock; seam-ON, still 403) ──
    @Test
    void domainLock_self_isDenied403_beforeAnyCasdoorRead() {
        // domainLock runs the always-on self guard first, so no Casdoor round-trip happens.
        asBrandXMod().post()
                .uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/mod:bob")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("a moderator may not ban themselves");
        assertThat(casdoor.requestCount()).isZero();
        verify(domainLocks, never()).lock(anyString(), anyString(), any());
    }

    // ════════════════════════════════════════════════════════════════════
    //  BODY-VALIDATION 400s on the seam-ON path (cheap re-assert — the 400
    //  must precede the guard/effect so no Casdoor read + no leaf write happen)
    // ════════════════════════════════════════════════════════════════════

    // ── domain-lock {role} path-var @Pattern violation → 400, never a Casdoor read ──
    @Test
    void domainLock_invalidRolePathVar_400_beforeGuardOrWrite() {
        asBrandXMod().post()
                .uri("/bff/mod/domain-lock/ROLE_BOGUS/victim")
                .exchange()
                .expectStatus().isBadRequest();
        // The bad path var is rejected by validation BEFORE the same-tenant guard runs,
        // so no Casdoor read and no admin-bff lock write happen.
        assertThat(casdoor.requestCount()).isZero();
        verify(domainLocks, never()).lock(anyString(), anyString(), any());
    }

    // ── lift body: blank target → ApiException badRequest in roleForPlatform? no: platform
    //    is required+@Pattern on BanRequest, so a bad platform is a clean 400 field error ──
    @Test
    void lift_badPlatform_400WithFieldError_beforeGuardOrWrite() {
        asBrandXMod().method(HttpMethod.DELETE).uri("/bff/mod/ban")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"irc\",\"target\":\"victim\"}")
                .exchange()
                .expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.platform").exists();
        assertThat(casdoor.requestCount()).isZero();
        verify(suspensions, never()).clear(anyString(), anyString());
    }

    /**
     * Supplies the REAL {@link ModService} + the REAL seam-ON {@link CasdoorRoleClient}
     * (pointed at the in-process {@link CasdoorRecorder} stub), so the controller drives the
     * production guard path. The seam is {@code enabled=true} with a brand→org map
     * ({@code brandx=orgx, brandy=orgy}) so a brand-X caller's reads key off {@code orgx}.
     */
    @TestConfiguration(proxyBeanMethods = false)
    static class SeamOnWiring {

        @Bean
        CasdoorRecorder casdoorRecorder() {
            return new CasdoorRecorder();
        }

        @Bean
        CasdoorRoleClient casdoorRoleClient(CasdoorRecorder recorder) {
            WebClient http = WebClient.builder()
                    .baseUrl("http://casdoor.stub")
                    .exchangeFunction(recorder)
                    .build();
            return new CasdoorRoleClient(http, "hugmesh", true,
                    Map.of("brandx", "orgx", "brandy", "orgy"));
        }

        @Bean
        ModService modService(AdminSuspensionClient suspensions, AdminDomainLockClient domainLocks,
                              CasdoorRoleClient roles, ModActionRepository audit,
                              MatrixAdminClient matrix, MastodonAdminClient mastodon) {
            // The owncast effector leg is not under test here — a Mockito mock keeps the
            // wiring inert (no bean/HTTP surface) exactly like the other client mocks.
            return new ModService(suspensions, domainLocks, roles, audit, matrix, mastodon,
                    org.mockito.Mockito.mock(systems.hugmesh.modbff.owncast.OwncastModClient.class));
        }
    }

    /**
     * In-process stub Casdoor (a {@link WebClient} {@link ExchangeFunction}) that answers
     * {@code /api/get-user} + {@code /api/get-role} from a fixed membership table and records
     * outbound requests so the test can prove the reads are caller-org-scoped. Mirrors the
     * {@code Wave2CasdoorSeamOnControllerTest.CasdoorRecorder} style.
     */
    static class CasdoorRecorder implements ExchangeFunction {
        private final List<String> getUserIds = new ArrayList<>();
        private final java.util.Set<String> knownUsers = java.util.concurrent.ConcurrentHashMap.newKeySet();
        private final Map<String, List<String>> roleMembers = new java.util.concurrent.ConcurrentHashMap<>();
        private final AtomicReference<Integer> count = new AtomicReference<>(0);

        void knownUser(String orgQualifiedId) { knownUsers.add(orgQualifiedId); }
        void roleMembers(String orgQualifiedRoleId, List<String> users) { roleMembers.put(orgQualifiedRoleId, users); }
        String lastGetUserId() { return getUserIds.isEmpty() ? null : getUserIds.get(getUserIds.size() - 1); }
        int requestCount() { return count.get(); }

        void reset() {
            getUserIds.clear();
            knownUsers.clear();
            roleMembers.clear();
            count.set(0);
        }

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            count.updateAndGet(c -> c + 1);
            String path = request.url().getPath();
            String query = request.url().getQuery() == null ? "" : request.url().getQuery();
            String id = query.startsWith("id=") ? query.substring(3).replace("%2F", "/") : query;
            String body;
            if (path.endsWith("/api/get-user")) {
                getUserIds.add(id);
                body = knownUsers.contains(id)
                        ? "{\"data\":{\"name\":\"" + id + "\"}}"
                        : "{\"data\":null}";
            } else if (path.endsWith("/api/get-role")) {
                List<String> users = roleMembers.getOrDefault(id, List.of());
                body = "{\"data\":{\"users\":[" + quoteJoin(users) + "]}}";
            } else {
                body = "{\"data\":null}";
            }
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                    .body(body).build());
        }

        private static String quoteJoin(List<String> users) {
            return users.stream().map(u -> "\"" + u + "\"").reduce((a, b) -> a + "," + b).orElse("");
        }
    }
}
