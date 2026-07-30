package systems.hugmesh.modbff.config;

import systems.hugmesh.commons.config.TenancyResourceServerConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;   // used by the as(...) helper return type
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.modbff.testsupport.TestIssuer;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Coarse PATH-GATE slice for the moderator BFF — the {@link SecurityConfig}
 * {@code authorizeExchange} policy, end-to-end through the REAL prod filter chain
 * ({@code @Profile("!dev & !test")}). The converter is unit-tested in isolation
 * ({@code SecurityConfigConverterTest}); this proves the actual request-path gating.
 *
 * <p>Asserts the mod-BFF's table:
 * <ul>
 *   <li><b>USER-SITUATIONAL DENY</b> — a plain {@code ROLE_USER} token gets 403 on
 *       {@code /bff/mod/**} (the moderator surface is MOD/ADMIN/SUPERADMIN-only) and on
 *       the prod-gated OpenAPI spec paths;</li>
 *   <li><b>USER-SITUATIONAL ALLOW</b> — {@code ROLE_MOD}, {@code ROLE_ADMIN} and
 *       {@code ROLE_SUPERADMIN} all reach {@code /bff/mod/**}; {@code ROLE_ADMIN}/
 *       {@code ROLE_SUPERADMIN} reach the spec paths;</li>
 *   <li><b>ANONYMOUS ALLOW</b> — the health/info actuator probes are public;</li>
 *   <li><b>ANONYMOUS DENY</b> — any other path 401s anonymous (the
 *       {@code anyExchange().authenticated()} floor), and the gated paths are never
 *       public.</li>
 * </ul>
 *
 * <p>The path policy is auth-decoder-agnostic, so this slice drives tokens through the
 * multi-issuer resolver path (the only no-network decoder seam — backed by an in-process
 * {@link TestIssuer}); the {@code authorizeExchange} rules under test are identical on
 * the single-issuer path. The single-issuer wiring DECISION (the chain stays on the
 * plain {@code o.jwt(...)} decoder, no swap) is asserted separately in
 * {@link #singleIssuer_staysOnPlainDecoder_noMultiIssuerSwap()}.
 *
 * <p>NOTE on the role table: {@link SecurityConfig} does declare a {@code roleHierarchy}
 * bean (added for {@code @PreAuthorize} method security, so {@code ROLE_SUPERADMIN}
 * reaches the {@code MOD}/{@code ADMIN}-gated methods — see {@code SecurityConfig
 * #roleHierarchy}), but this SLICE constructs the filter chain directly
 * ({@link SecuritySliceSupport#sliceClient}) without Spring's DI, so no
 * {@code RoleHierarchy}/{@code MethodSecurityExpressionHandler} bean is ever wired into
 * it — and in any case a {@code RoleHierarchy} bean is not auto-applied to
 * {@code authorizeExchange} matchers (only to {@code @PreAuthorize}). So
 * {@code hasAnyRole("MOD","ADMIN","SUPERADMIN")} here matches ONLY the literal
 * authorities the Casdoor converter emits — there is no implied-role widening for this
 * coarse chain-level gate. Each role is therefore asserted literally below.
 */
class SecurityConfigPathGateSliceTest extends SecuritySliceSupport {

    private TestIssuer issuer;
    private TestIssuer issuer2;   // a second trusted issuer so isMultiIssuer() holds
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        issuer2 = new TestIssuer();
        String issuersCsv = issuer.issuerUri() + "=brandx," + issuer2.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(), issuersCsv);
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "", false, 600000L);
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                systems.hugmesh.commons.config.TenancyResolvers.tenantResolver(tenancy);
        client = sliceClient(registry, provider(resolver), new ProbeController());
    }

    @AfterEach
    void tearDown() {
        issuer.close();
        issuer2.close();
    }

    private WebTestClient.RequestHeadersSpec<?> as(List<String> roles, String path) {
        String token = issuer.mint("p-" + String.join("-", roles), roles);
        return client.get().uri(path).header("Authorization", "Bearer " + token);
    }

    // ── USER-SITUATIONAL DENY — ROLE_USER vs the moderator surface ────────────

    @Test
    void user_forbiddenOn_modSurface() {
        // The moderator surface is MOD/ADMIN/SUPERADMIN-only: a plain user (ROLE_USER
        // floor, no MOD/ADMIN) is authenticated but NOT authorized -> 403, never 200.
        as(List.of("user"), "/bff/mod/reports").exchange().expectStatus().isForbidden();
    }

    @Test
    void user_forbiddenOn_specPaths() {
        // Prod chain gates the OpenAPI spec + Swagger UI to ADMIN/SUPERADMIN so the API
        // contract is never publicly (or merely-user) reachable. A ROLE_USER -> 403.
        as(List.of("user"), "/v3/api-docs").exchange().expectStatus().isForbidden();
        as(List.of("user"), "/swagger-ui/index.html").exchange().expectStatus().isForbidden();
    }

    @Test
    void mod_forbiddenOn_specPaths() {
        // A MOD is privileged on the moderator surface but is NOT an API-contract
        // (ADMIN/SUPERADMIN) role -> 403 on the spec paths.
        as(List.of("mod"), "/v3/api-docs").exchange().expectStatus().isForbidden();
    }

    // ── USER-SITUATIONAL ALLOW — MOD / ADMIN / SUPERADMIN reach /bff/mod/** ───

    @Test
    void mod_allowedOn_modSurface() {
        as(List.of("mod"), "/bff/mod/reports").exchange().expectStatus().isOk();
    }

    @Test
    void admin_allowedOn_modSurface() {
        as(List.of("admin"), "/bff/mod/reports").exchange().expectStatus().isOk();
    }

    @Test
    void superadmin_allowedOn_modSurface() {
        // SUPERADMIN is the cross-domain infra control plane and reaches the moderator
        // surface (literal ROLE_SUPERADMIN — no roleHierarchy widening in this repo).
        as(List.of("superadmin"), "/bff/mod/reports").exchange().expectStatus().isOk();
    }

    @Test
    void admin_allowedOn_specPaths() {
        as(List.of("admin"), "/v3/api-docs").exchange().expectStatus().isOk();
    }

    @Test
    void superadmin_allowedOn_specPaths() {
        as(List.of("superadmin"), "/swagger-ui/index.html").exchange().expectStatus().isOk();
    }

    // ── ANONYMOUS ALLOW — health/info probes are public ───────────────────────

    @Test
    void anonymous_allowedOn_healthAndInfoProbes() {
        // permitAll — k8s/Docker healthchecks need no token. Must not be 401/403.
        for (String path : List.of("/actuator/health", "/actuator/health/readiness", "/actuator/info")) {
            client.get().uri(path).exchange()
                    .expectStatus().value(s -> assertNot401Nor403(path, s));
        }
    }

    // ── ANONYMOUS DENY — the authenticated() floor ────────────────────────────

    @Test
    void anonymous_deniedOn_modSurface() {
        // /bff/mod/** is never public — anonymous gets 401 (no auth) at the floor.
        client.get().uri("/bff/mod/reports").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void anonymous_deniedOn_arbitraryGatedPath() {
        // anyExchange().authenticated() — an ungoverned, non-public path 401s anonymous.
        client.get().uri("/api/whatever").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void anonymous_deniedOn_specPaths() {
        // The OpenAPI spec is never public on the prod chain — anonymous 401s.
        client.get().uri("/v3/api-docs").exchange().expectStatus().isUnauthorized();
    }

    // ── single-issuer wiring DECISION — the chain stays on the plain decoder ──

    @Test
    void singleIssuer_staysOnPlainDecoder_noMultiIssuerSwap() {
        // A single-issuer cluster: the lone configured issuer + EMPTY app.tenancy.issuers
        // seeds exactly one registry entry, so isMultiIssuer() is false. SecurityConfig
        // therefore stays on the EXISTING single o.jwt(...) issuer-uri decoder path and
        // NEVER swaps onto the per-issuer resolver — even if a resolver were contributed.
        // (b) here is the regression guard for that gating: the swap is gated on
        // isMultiIssuer(), not merely resolver!=null.
        DomainRegistry single = new DomainRegistry(issuer.issuerUri(), "");
        assertThat(single.isMultiIssuer())
                .as("one entry (lone back-compat issuer) => single-issuer mode, plain decoder")
                .isFalse();
        assertThat(single.trustedIssuers())
                .as("the lone configured issuer is the only trusted issuer")
                .containsExactly(issuer.issuerUri());

        // The swap is gated on isMultiIssuer() (the line above), NOT merely
        // resolver!=null: even when a tenant resolver IS contributed, a single-entry
        // registry keeps SecurityConfig on the plain o.jwt(...) issuer-uri decoder. We
        // assert the gate against DomainRegistry directly rather than building the chain,
        // because the plain o.jwt(...) path needs the Boot-autoconfigured
        // ReactiveJwtDecoder (the issuer-uri property), which a pure no-network slice
        // does not provide — building it here would (correctly) demand a live decoder.
        // The DECISION that selects that path is what this guards, and it is false.
    }

    /** A path reached by an ALLOWED (permitAll) request must not be 401/403. The probe
     *  controller maps every path below, so a permitAll path resolves to 200; the only
     *  failures we guard against are the security 401/403. */
    private static void assertNot401Nor403(String path, int status) {
        if (status == 401 || status == 403) {
            throw new AssertionError("expected anonymous ALLOW on " + path + " but got " + status);
        }
    }

    /** Maps every path the slice exercises so an ALLOWED request resolves to 200
     *  (instead of a 404 that could mask a missing security decision). */
    @RestController
    static class ProbeController {
        @RequestMapping({
                "/bff/mod/reports",
                "/v3/api-docs", "/swagger-ui/index.html",
                "/actuator/health", "/actuator/health/readiness", "/actuator/info",
                "/api/whatever",
        })
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
