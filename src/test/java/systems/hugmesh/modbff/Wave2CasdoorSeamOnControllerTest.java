package systems.hugmesh.modbff;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
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
import systems.hugmesh.modbff.config.SecurityConfig;
import systems.hugmesh.modbff.external.MastodonAdminClient;
import systems.hugmesh.modbff.external.MatrixAdminClient;
import systems.hugmesh.modbff.federation.FederationApiClient;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.modbff.service.ModService;
import systems.hugmesh.modbff.web.ApiExceptionHandler;

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
 * CasdoorRoleClient SEAM-ON path, exercised at the CONTROLLER layer — the REAL
 * {@link ModService} guards driving the REAL {@link CasdoorRoleClient} (constructed
 * {@code enabled=true} against an in-process stub Casdoor), with only the leaf clients
 * (admin-bff suspension/domain-lock, the audit repo) mocked. This is the production
 * cross-domain BOLA/BFLA guard (A01 / CWE-639) as the HTTP boundary enforces it — NOT
 * the stub-seam-off path the other web-slices use (where {@code ModService} is mocked).
 *
 * <p>The acting moderator carries a real issuer-derived {@code DOMAIN_brandx} authority,
 * so {@link systems.hugmesh.modbff.security.Roles#domainOf} resolves "brandx" and the
 * branded-caller leg of {@code ModService.guardSameTenant} runs the REAL Casdoor
 * {@code GET /api/get-user?id=<org>/<target>} read (keyed off the caller's brand org via
 * the {@code domainOrgMap}). The stub answers from a fixed membership table, so:
 *
 * <ul>
 *   <li><b>CROSS-DOMAIN DENY</b> — a target who lives in brand-Y's org resolves ABSENT
 *       when read against brand-X's org → {@code belongsToDomain} false → the same-tenant
 *       guard 403s BEFORE any admin-bff write. The DENY assertion is at the HTTP layer
 *       (403 {error}) AND verified by the admin-bff suspension write NEVER being called.</li>
 *   <li><b>PRIVILEGED-TARGET DENY</b> — a same-tenant target who holds
 *       {@code ROLE_ADMIN}/{@code ROLE_MOD} in brand-X's org → the real
 *       {@code isPrivileged} read returns true → 403, again before any write.</li>
 *   <li><b>SAME-TENANT ALLOW</b> — a non-privileged target in the caller's brand org
 *       passes both real Casdoor reads → the ban proceeds to the (mocked) admin-bff write
 *       → 202 pending-reconcile.</li>
 *   <li><b>SEAM-ON tenant read keys off the CALLER's brand org</b> — the recorded
 *       outbound get-user URL is org-qualified with brand-X's org, proving the read is
 *       caller-scoped (not the static org), the fix that makes the cross-tenant deny
 *       authoritative.</li>
 * </ul>
 */
@WebFluxTest(controllers = ModController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ApiExceptionHandler.class,
        Wave2CasdoorSeamOnControllerTest.SeamOnWiring.class})
class Wave2CasdoorSeamOnControllerTest {

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
    @MockitoBean FederationApiClient federation;
    @MockitoBean MatrixAdminClient matrix;
    @MockitoBean MastodonAdminClient mastodon;
    @MockitoBean ModActionRepository audit;
    @MockitoBean AdminSuspensionClient suspensions;
    @MockitoBean AdminDomainLockClient domainLocks;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;     // satisfies oauth2 resource-server wiring

    /** The shared recorder the stub Casdoor answers from + records outbound requests to. */
    @Autowired CasdoorRecorder casdoor;

    @org.junit.jupiter.api.BeforeEach
    void resetRecorder() {
        // The recorder is a singleton bean shared across the class's tests; reset its
        // membership table + request log so each test asserts only its OWN traffic.
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

    private void stubAuditRecord() {
        // The same-tenant guard runs BEFORE the dedup write, so a DENY never reaches this;
        // an ALLOW does. Return a fresh pending ban row so the ALLOW path proceeds to the
        // (mocked) admin-bff write.
        ModAction row = new ModAction("b-1", "mod:bob", "access.suspend", "access", "alice",
                "abuse", "pending", LocalDateTime.parse("2026-06-06T00:00:00"),
                "dk", "user", null, "pending", "brandx", null, null);
        when(audit.recordBan(anyString(), anyString(), anyString(), anyString(), anyString(),
                any(), anyString(), any(), anyString(), eq("brandx")))
                .thenReturn(Mono.just(new ModActionRepository.RecordedBan(row, true)));
    }

    // ── CROSS-DOMAIN DENY: a brand-Y target read against brand-X's org is ABSENT ──
    @Test
    void ban_crossDomainTarget_isDenied403_noAdminBffWrite() {
        // The stub only knows brand-Y's org (orgy) members; keyed off brand-X's org (orgx)
        // the get-user for orgx/victim returns data:null → belongsToDomain false → 403.
        casdoor.knownUser("orgy/victim");
        asBrandXMod().post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"victim\",\"reason\":\"abuse\"}")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error")
                .isEqualTo("target is not in the moderator's domain and cannot be moderated cross-tenant");
        // DENY assertion: the cross-tenant ban NEVER reached the admin-bff desired-state
        // write nor the audit dedup row — the guard short-circuited first.
        verify(suspensions, never()).suspend(anyString(), anyString(), any(), any());
        verify(audit, never()).recordBan(anyString(), anyString(), anyString(), anyString(),
                anyString(), any(), anyString(), any(), anyString(), anyString());
        // SEAM-ON proof: the tenant read was keyed off the CALLER's brand org (orgx), not
        // the static org — the get-user id is orgx/victim.
        assertThat(casdoor.lastGetUserId()).isEqualTo("orgx/victim");
    }

    // ── SENSITIVITY (regression sentinel): the SAME request flips to ALLOW when
    //    the victim IS a member of the caller's org — proving the 403 above is caused
    //    by the cross-tenant membership result, not anything incidental. This paired
    //    ALLOW pins the DENY test's dependency on the same-tenant guard, so a future
    //    weakening of cross-brand isolation (the A01/CWE-639 regression) cannot leave
    //    the deny test passing vacuously. ──
    @Test
    void ban_sameNameButInCallersOrg_proceeds202_provingDenyIsLoadBearing() {
        // SAME target string + SAME brand-X caller as the cross-domain DENY test, but now
        // 'victim' is registered PRESENT in the CALLER's org (orgx) and non-privileged →
        // belongsToDomain true → the guard passes → 202 (not the 403 of the deny test).
        casdoor.knownUser("orgx/victim");
        casdoor.roleMembers("orgx/ROLE_ADMIN", List.of());
        casdoor.roleMembers("orgx/ROLE_MOD", List.of());
        stubAuditRecord();
        when(suspensions.suspend(eq("ROLE_MATRIX"), eq("victim"), any(), any()))
                .thenReturn(Mono.just(SuspensionOutcome.PENDING));
        asBrandXMod().post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"victim\",\"reason\":\"abuse\"}")
                .exchange()
                .expectStatus().isAccepted();
        verify(suspensions).suspend(eq("ROLE_MATRIX"), eq("victim"), any(), any());
        // Read still keyed off orgx (caller-scoped) — same id as the deny test, opposite result.
        assertThat(casdoor.lastGetUserId()).isEqualTo("orgx/victim");
    }

    // ── PRIVILEGED-TARGET DENY: a same-tenant ROLE_ADMIN target ──────────────
    @Test
    void ban_privilegedSameTenantTarget_isDenied403() {
        // The target IS in brand-X's org (so the same-tenant guard passes) AND holds
        // ROLE_ADMIN in brand-X's org → the real isPrivileged read returns true → 403.
        casdoor.knownUser("orgx/anadmin");
        casdoor.roleMembers("orgx/ROLE_ADMIN", List.of("orgx/anadmin"));
        asBrandXMod().post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"anadmin\",\"reason\":\"abuse\"}")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error")
                .isEqualTo("target holds ROLE_ADMIN or ROLE_MOD and cannot be banned by a moderator");
        verify(suspensions, never()).suspend(anyString(), anyString(), any(), any());
    }

    // ── SAME-TENANT ALLOW: a non-privileged in-org target → 202 ──────────────
    @Test
    void ban_sameTenantNonPrivilegedTarget_proceeds202() {
        // alice IS a member of brand-X's org and holds NEITHER privileged role → both real
        // Casdoor reads pass → the ban proceeds to the (mocked) admin-bff write → 202.
        casdoor.knownUser("orgx/alice");
        casdoor.roleMembers("orgx/ROLE_ADMIN", List.of());
        casdoor.roleMembers("orgx/ROLE_MOD", List.of());
        stubAuditRecord();
        when(suspensions.suspend(eq("ROLE_MATRIX"), eq("alice"), any(), any()))
                .thenReturn(Mono.just(SuspensionOutcome.PENDING));
        asBrandXMod().post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"alice\",\"reason\":\"abuse\"}")
                .exchange()
                .expectStatus().isAccepted()
                .expectBody()
                .jsonPath("$.state").isEqualTo("pending-reconcile")
                .jsonPath("$.action.action").isEqualTo("access.suspend");
        verify(suspensions).suspend(eq("ROLE_MATRIX"), eq("alice"), any(), any());
    }

    // ── SELF-BAN short-circuits BEFORE any Casdoor read (seam-ON, still 403) ──
    @Test
    void ban_self_isDenied403_beforeAnyCasdoorRead() {
        // The always-on self-ban guard runs first, so no Casdoor round-trip happens.
        asBrandXMod().post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"mod:bob\",\"reason\":\"x\"}")
                .exchange()
                .expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("a moderator may not ban themselves");
        assertThat(casdoor.requestCount()).isZero();   // self-ban short-circuits before Casdoor
        verify(suspensions, never()).suspend(anyString(), anyString(), any(), any());
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
            // enabled=TRUE — the SEAM-ON path, with per-brand org mapping so a brand-X
            // caller's privileged + tenant reads key off orgx (not the static 'hugmesh').
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
     * {@code CasdoorRoleClientTest.Recorder} style.
     */
    static class CasdoorRecorder implements ExchangeFunction {
        private final List<String> getUserIds = new ArrayList<>();
        private final java.util.Set<String> knownUsers = java.util.concurrent.ConcurrentHashMap.newKeySet();
        private final Map<String, List<String>> roleMembers = new java.util.concurrent.ConcurrentHashMap<>();
        private final AtomicReference<Integer> count = new AtomicReference<>(0);

        /** Register an org-qualified user id (e.g. {@code orgx/alice}) the stub will resolve PRESENT. */
        void knownUser(String orgQualifiedId) { knownUsers.add(orgQualifiedId); }

        /** Register the {@code users} list for an org-qualified role id (e.g. {@code orgx/ROLE_ADMIN}). */
        void roleMembers(String orgQualifiedRoleId, List<String> users) { roleMembers.put(orgQualifiedRoleId, users); }

        String lastGetUserId() { return getUserIds.isEmpty() ? null : getUserIds.get(getUserIds.size() - 1); }
        int requestCount() { return count.get(); }

        /** Reset between tests — the bean is a context singleton shared across the class. */
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
