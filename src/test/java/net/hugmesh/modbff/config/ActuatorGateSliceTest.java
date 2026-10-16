package net.hugmesh.modbff.config;

import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.testsupport.TestIssuer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * ACTUATOR GATE — every {@code /actuator/**} path other than the public
 * {@code health}/{@code info} probes is ADMIN/SUPERADMIN-only, decided by the
 * {@link SecurityConfig} filter chain itself and NOT by the actuator exposure list.
 *
 * <p>The probe controller below maps the whole {@code /actuator} subtree to a handler
 * that answers 200, standing in for "an endpoint somebody exposed" (a widened
 * {@code management.endpoints.web.exposure.include}, an env override, a future
 * starter). Without the rule, {@code anyExchange().authenticated()} would hand that
 * handler to every logged-in ROLE_USER; the assertions here fail loudly in that case
 * because the handler genuinely answers 200.
 */
class ActuatorGateSliceTest extends SecuritySliceSupport {

    /** Endpoints that leak internals when exposed (plus the bare {@code /actuator} index). */
    private static final List<String> GATED = List.of(
            "/actuator", "/actuator/env", "/actuator/beans", "/actuator/heapdump",
            "/actuator/metrics", "/actuator/loggers", "/actuator/prometheus",
            "/actuator/threaddump", "/actuator/configprops", "/actuator/mappings");

    private TestIssuer issuer;
    private TestIssuer issuer2;
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        issuer2 = new TestIssuer();
        String issuersCsv = issuer.issuerUri() + "=brandx," + issuer2.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(), issuersCsv);
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "", false, 600000L);
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                net.hugmesh.commons.config.TenancyResolvers.tenantResolver(tenancy);
        client = sliceClient(registry, provider(resolver), new ActuatorProbe());
    }

    @AfterEach
    void tearDown() {
        issuer.close();
        issuer2.close();
    }

    private WebTestClient.RequestHeadersSpec<?> as(String role, String path) {
        String token = issuer.mint("p-" + role, List.of(role));
        return client.get().uri(path).header("Authorization", "Bearer " + token);
    }

    // ── the exploit: a plain logged-in user reaching an exposed actuator endpoint ──

    @Test
    void user_isForbiddenOn_everyGatedActuatorPath() {
        for (String path : GATED) {
            as("user", path).exchange().expectStatus().isForbidden();
        }
    }

    @Test
    void mod_isForbiddenOn_everyGatedActuatorPath() {
        for (String path : GATED) {
            as("mod", path).exchange().expectStatus().isForbidden();
        }
    }

    @Test
    void service_isForbiddenOn_everyGatedActuatorPath() {
        // ROLE_SERVICE is a machine principal with no edge to ADMIN.
        for (String path : GATED) {
            as("service", path).exchange().expectStatus().isForbidden();
        }
    }

    @Test
    void anonymous_isUnauthorizedOn_everyGatedActuatorPath() {
        for (String path : GATED) {
            client.get().uri(path).exchange().expectStatus().isUnauthorized();
        }
    }

    @Test
    void admin_andSuperadmin_reachGatedActuatorPaths() {
        for (String role : List.of("admin", "superadmin")) {
            for (String path : GATED) {
                as(role, path).exchange().expectStatus().isOk();
            }
        }
    }

    // ── the public probes stay public ──────────────────────────────────────────

    @Test
    void healthAndInfo_stayPublic() {
        for (String path : List.of("/actuator/health", "/actuator/health/liveness",
                "/actuator/health/readiness", "/actuator/info")) {
            client.get().uri(path).exchange().expectStatus().isOk();
        }
    }

    // ── spellings: the SAME decision whichever way the path is written ─────────

    @Test
    void trailingSlash_isGatedLikeTheBarePath() {
        as("user", "/actuator/env/").exchange().expectStatus().isForbidden();
        client.get().uri("/actuator/env/").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void percentEncodedSegment_isGatedLikeTheDecodedPath() {
        // %65 == 'e': the router decodes the segment before matching, so must the gate.
        // The strict firewall may refuse the encoded spelling outright (400); if it lets it
        // through the gate must answer exactly as it does for the decoded path.
        var user = as("user", "/actuator/%65nv").exchange().returnResult(String.class);
        assertThat(user.getStatus().value()).isIn(Set.of(400, 403));
        var anon = client.get().uri("/actuator/%65nv").exchange().returnResult(String.class);
        assertThat(anon.getStatus().value()).isIn(Set.of(400, 401));
    }

    @Test
    void dotSegmentsAndSemicolonParamsBehindThePublicProbePrefix_neverReachTheHandler() {
        // /actuator/health/** is permitAll, so a traversal out of it must not land on /env.
        // The strict firewall refuses these outright (400); if one ever normalises into the
        // gated subtree the rule answers 403/401. A path that is no actuator path at all for
        // the router either (empty or dot first segment) is an unmapped 404. Never 200.
        Set<Integer> refused = Set.of(400, 401, 403, 404);
        for (String path : List.of(
                "/actuator/health/../env",
                "/actuator/health/%2e%2e/env",
                "/actuator/health/%2E%2E/env",
                "/actuator/health/..;/env",
                "/actuator/health/%252e%252e/env",
                "/actuator/env;x=y",
                "/actuator;x=y/env",
                "/actuator%2Fenv",
                "/actuator%252Fenv",
                "//actuator/env",
                "/./actuator/env")) {
            for (String role : List.of("user", "mod")) {
                var res = as(role, path).exchange().returnResult(String.class);
                assertThat(res.getStatus().value()).as("%s as %s", path, role).isIn(refused);
            }
            var anon = client.get().uri(path).exchange().returnResult(String.class);
            assertThat(anon.getStatus().value()).as("%s anonymous", path).isIn(refused);
        }
    }

    @Test
    void differentCase_neverReachesTheHandler() {
        // Both the router and the gate are case-sensitive, so /ACTUATOR/env is no actuator
        // path at all: the floor (401/403) or an unmapped 404 — never the handler's 200.
        for (String path : List.of("/ACTUATOR/env", "/Actuator/env", "/actuator/ENV")) {
            var res = as("user", path).exchange().returnResult(String.class);
            assertThat(res.getStatus().value()).as(path).isIn(Set.of(401, 403, 404));
        }
    }

    /** Maps the whole actuator subtree to a 200 handler so an ALLOWED request is a real
     *  200 and a missing rule cannot hide behind a 404. */
    @RestController
    static class ActuatorProbe {
        @RequestMapping({"/actuator", "/actuator/{*rest}"})
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
