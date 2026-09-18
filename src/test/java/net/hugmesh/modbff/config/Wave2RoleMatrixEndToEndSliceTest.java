package net.hugmesh.modbff.config;

import net.hugmesh.commons.config.TenancyResourceServerConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.modbff.ModController;
import net.hugmesh.modbff.audit.ModAction;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.federation.FederationApiClient;
import net.hugmesh.modbff.federation.FederationManifestDto;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.service.ModService;
import net.hugmesh.modbff.testsupport.Wave2TestIssuer;

import java.time.LocalDateTime;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * END-TO-END role matrix on the REAL {@link ModController} endpoints, driven by REAL
 * minted tokens through the REAL prod {@link SecurityConfig#filterChain} +
 * {@link TenancyResourceServerConfig} multi-issuer resolver (two
 * {@link Wave2TestIssuer}s). Unlike the existing {@code @WebFluxTest} controller slices
 * (which inject Spring-Security's {@code mockJwt()} authorities directly), here the
 * authorities + the {@code DOMAIN_<x>} scope are produced by the production converter
 * from a cryptographically-validated token — so the role gate AND the issuer-derived
 * tenant scope are exercised end-to-end at the HTTP boundary.
 *
 * <p>The role matrix (per the test standard) on the actual mod surface:
 * <ul>
 *   <li><b>USER-SITUATIONAL DENY</b> — a plain {@code ROLE_USER} token is authenticated
 *       but 403 on every mod endpoint (the MOD floor) — list/recommend/refer/block/
 *       modules/audit/ban/domain-lock;</li>
 *   <li><b>USER-SITUATIONAL ALLOW</b> — a {@code ROLE_MOD} token reaches the read
 *       endpoints (list/modules/audit); an {@code ROLE_ADMIN} token likewise;</li>
 *   <li><b>CROSS-USER ISOLATION (the DENY that matters)</b> — a brand-X MOD's audit read
 *       is SCOPED to {@code DOMAIN_brandx} (the converter stamped it from issuer X), so
 *       it calls {@code listForDomain("brandx")} and NEVER the unscoped cross-brand
 *       {@code list()}; a brand-Y MOD is scoped to {@code "brandy"}. The brand is taken
 *       from the VALIDATED issuer, never a request input;</li>
 *   <li><b>CROSS-USER ISOLATION (SUPERADMIN)</b> — a SUPERADMIN token reads UNSCOPED
 *       ({@code list()}) across every brand (the infra control plane);</li>
 *   <li><b>UNKNOWN ISSUER 401</b> — a token from an untrusted issuer 401s on the mod
 *       surface, fail-closed, before any role/domain decision.</li>
 * </ul>
 */
class Wave2RoleMatrixEndToEndSliceTest extends Wave2SecuritySliceSupport {

    private Wave2TestIssuer brandX;
    private Wave2TestIssuer brandY;
    private Wave2TestIssuer untrusted;
    private WebTestClient client;

    private FederationApiClient federation;
    private ModActionRepository audit;

    @BeforeEach
    void setUp() {
        brandX = new Wave2TestIssuer();
        brandY = new Wave2TestIssuer();
        untrusted = new Wave2TestIssuer();
        String issuersCsv = brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(brandX.issuerUri(), issuersCsv);
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "", false, 600000L);
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                net.hugmesh.commons.config.TenancyResolvers.tenantResolver(tenancy);

        // Leaf collaborators are mocked; the controller + (for the ban guard) the service
        // run for real. The READ endpoints (audit/modules/list) need no service.
        federation = mock(FederationApiClient.class);
        MastodonAdminClient mastodon = mock(MastodonAdminClient.class);
        audit = mock(ModActionRepository.class);
        ModService modService = mock(ModService.class);

        ModController controller = new ModController(federation, mastodon, audit, modService);
        client = sliceClient(registry, provider(resolver), controller);
    }

    @AfterEach
    void tearDown() {
        brandX.close();
        brandY.close();
        untrusted.close();
    }

    private WebTestClient.RequestHeadersSpec<?> get(Wave2TestIssuer iss, List<String> roles, String path) {
        return client.get().uri(path).header("Authorization", "Bearer " + iss.mint("p", roles));
    }

    private WebTestClient.RequestBodySpec post(Wave2TestIssuer iss, List<String> roles, String path) {
        return client.post().uri(path).header("Authorization", "Bearer " + iss.mint("p", roles));
    }

    private static ModAction row(String domain) {
        return new ModAction("a-1", "p", "matrix.block-user", "matrix", "@x:y",
                "abuse", "stubbed", LocalDateTime.parse("2026-06-06T00:00:00"),
                null, null, null, null, domain);
    }

    // ── USER-SITUATIONAL DENY — a plain ROLE_USER is 403 on the whole surface ──
    @Test
    void user_forbiddenOn_everyModEndpoint() {
        List<String> u = List.of("user");
        get(brandX, u, "/bff/mod/moderation").exchange().expectStatus().isForbidden();
        get(brandX, u, "/bff/mod/modules").exchange().expectStatus().isForbidden();
        get(brandX, u, "/bff/mod/audit").exchange().expectStatus().isForbidden();
        post(brandX, u, "/bff/mod/moderation").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"instance-block\",\"target\":\"evil.example\"}")
                .exchange().expectStatus().isForbidden();
        post(brandX, u, "/bff/mod/moderation/7/refer").exchange().expectStatus().isForbidden();
        post(brandX, u, "/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\",\"target\":\"@x:y\"}")
                .exchange().expectStatus().isForbidden();
        post(brandX, u, "/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"alice\"}")
                .exchange().expectStatus().isForbidden();
        post(brandX, u, "/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/alice")
                .exchange().expectStatus().isForbidden();
        // A plain user never reaches the service nor the audit repo — the gate denied first.
        verify(audit, never()).listForDomain(anyString(), anyInt());
        verify(audit, never()).list(anyInt());
    }

    // ── USER-SITUATIONAL ALLOW — a MOD reaches the read endpoints ──────────────
    @Test
    void mod_allowedOn_readEndpoints() {
        when(federation.listModeration(null)).thenReturn(Flux.empty());
        when(federation.manifest()).thenReturn(Mono.just(new FederationManifestDto("t", List.of())));
        when(audit.listForDomain(eq("brandx"), anyInt())).thenReturn(Flux.just(row("brandx")));
        get(brandX, List.of("mod"), "/bff/mod/moderation").exchange().expectStatus().isOk();
        get(brandX, List.of("mod"), "/bff/mod/modules").exchange().expectStatus().isOk();
        get(brandX, List.of("mod"), "/bff/mod/audit").exchange().expectStatus().isOk();
    }

    @Test
    void admin_allowedOn_readEndpoints() {
        when(audit.listForDomain(eq("brandx"), anyInt())).thenReturn(Flux.empty());
        get(brandX, List.of("admin"), "/bff/mod/audit").exchange().expectStatus().isOk();
    }

    // ── CROSS-USER ISOLATION — the brand is taken from the VALIDATED issuer ────
    @Test
    void brandXMod_auditReadIsScopedToBrandX_neverUnscoped() {
        // The DENY that matters: a brand-X MOD's converter-stamped DOMAIN_brandx drives a
        // SCOPED read (listForDomain("brandx")); the unscoped cross-brand list() is NEVER
        // called for a per-domain principal. The domain came from issuer X, not the request.
        when(audit.listForDomain(eq("brandx"), anyInt())).thenReturn(Flux.just(row("brandx")));
        get(brandX, List.of("mod"), "/bff/mod/audit").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.actions[0].domain").isEqualTo("brandx");
        verify(audit).listForDomain(eq("brandx"), anyInt());
        verify(audit, never()).list(anyInt());
        verify(audit, never()).listForDomain(eq("brandy"), anyInt());
    }

    @Test
    void brandYMod_auditReadIsScopedToBrandY() {
        when(audit.listForDomain(eq("brandy"), anyInt())).thenReturn(Flux.just(row("brandy")));
        get(brandY, List.of("mod"), "/bff/mod/audit").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.actions[0].domain").isEqualTo("brandy");
        verify(audit).listForDomain(eq("brandy"), anyInt());
        verify(audit, never()).listForDomain(eq("brandx"), anyInt());
        verify(audit, never()).list(anyInt());
    }

    // ── CROSS-USER ISOLATION (SUPERADMIN) — unscoped across every brand ────────
    @Test
    void superadmin_auditReadIsUnscoped_acrossEveryBrand() {
        when(audit.list(anyInt())).thenReturn(Flux.just(row("brandx"), row("brandy")));
        // The token is minted by brand X, but a SUPERADMIN bypasses per-domain scoping.
        get(brandX, List.of("superadmin"), "/bff/mod/audit").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[0].domain").isEqualTo("brandx")
                .jsonPath("$.actions[1].domain").isEqualTo("brandy");
        verify(audit).list(anyInt());
        verify(audit, never()).listForDomain(anyString(), anyInt());
    }

    // ── SUPERADMIN reaches the hasAnyRole('MOD','ADMIN') methods via the hierarchy ─
    @Test
    void superadmin_allowedOn_moderationQueue_viaRoleHierarchy() {
        // REGRESSION GUARD: the /bff/mod/** chain admits SUPERADMIN, and the SecurityConfig
        // documents that the cross-domain SUPERADMIN reaches the mod surface. But the
        // method-level @PreAuthorize is hasAnyRole('MOD','ADMIN') (NOT listing SUPERADMIN),
        // so without the RoleHierarchy bean (ROLE_SUPERADMIN > ROLE_MOD/ROLE_ADMIN) a
        // superadmin token passes the chain yet 403s at the method — only /audit (which
        // lists SUPERADMIN explicitly) would work. With the hierarchy wired into method
        // security, superadmin reaches the moderation queue too.
        when(federation.listModeration(null)).thenReturn(Flux.empty());
        when(federation.manifest()).thenReturn(Mono.just(new FederationManifestDto("t", List.of())));
        get(brandX, List.of("superadmin"), "/bff/mod/moderation").exchange().expectStatus().isOk();
        get(brandX, List.of("superadmin"), "/bff/mod/modules").exchange().expectStatus().isOk();
    }

    // ── UNKNOWN ISSUER 401 — fail-closed before any role/domain decision ───────
    @Test
    void unknownIssuer_is401_onModSurface() {
        client.get().uri("/bff/mod/audit")
                .header("Authorization", "Bearer " + untrusted.mint("intruder", List.of("admin", "superadmin")))
                .exchange().expectStatus().isUnauthorized();
        verify(audit, never()).list(anyInt());
        verify(audit, never()).listForDomain(anyString(), anyInt());
    }

    // ── DELETE ban/domain-lock also gated to the MOD floor (USER DENY) ─────────
    @Test
    void user_forbiddenOn_deleteBanAndDomainUnlock() {
        client.method(HttpMethod.DELETE).uri("/bff/mod/ban")
                .header("Authorization", "Bearer " + brandX.mint("p", List.of("user")))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"alice\"}")
                .exchange().expectStatus().isForbidden();
        client.method(HttpMethod.DELETE).uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/alice")
                .header("Authorization", "Bearer " + brandX.mint("p", List.of("user")))
                .exchange().expectStatus().isForbidden();
    }
}
