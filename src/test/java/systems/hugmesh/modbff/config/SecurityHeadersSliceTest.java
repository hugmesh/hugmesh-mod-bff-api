package systems.hugmesh.modbff.config;

import systems.hugmesh.commons.config.TenancyResourceServerConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.modbff.testsupport.TestIssuer;

import java.util.List;

/**
 * Hardened-HTTP-headers slice for the moderator BFF — proves the
 * {@link SecurityConfig#hardenedHeaders} block is wired into the REAL prod filter chain
 * ({@code @Profile("!dev & !test")}) and emits on actual responses, end-to-end through
 * {@link org.springframework.security.web.server.WebFilterChainProxy}.
 *
 * <p>Asserts the BFF defensive-minimum from the org security plan (OWASP A05 / ASVS
 * V14.4 / NIST 800-228) on a pure-JSON resource server that always sits behind the
 * TLS-terminating gateway:
 * <ul>
 *   <li><b>ADDED</b> — {@code Content-Security-Policy: default-src 'none'; frame-ancestors 'none'}
 *       (no-content API CSP, defense-in-depth);</li>
 *   <li><b>KEPT (Spring secure defaults, NOT disabled)</b> — {@code X-Content-Type-Options: nosniff}
 *       and {@code X-Frame-Options: DENY};</li>
 *   <li><b>OMITTED (correct for a no-document BFF behind the TLS edge)</b> —
 *       {@code Strict-Transport-Security} (HSTS lives only at the gateway TLS front door)
 *       and {@code Permissions-Policy} (no document to govern).</li>
 * </ul>
 *
 * <p>Headers are an authorization-decision-agnostic, ALWAYS-applied concern, so they
 * must be present on BOTH an authorized 200 AND an unauthenticated 401 — the slice
 * asserts both, and re-asserts the {@code anyExchange().authenticated()} fail-closed
 * floor still 401s anonymous (header hardening is purely additive — it changes no authz
 * rule or CSRF posture).
 */
class SecurityHeadersSliceTest extends SecuritySliceSupport {

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

    // ── hardened headers PRESENT on an authorized 200 ─────────────────────────

    @Test
    void hardenedHeaders_presentOnAuthorized200() {
        String token = issuer.mint("p-mod", List.of("mod"));
        client.get().uri("/bff/mod/reports").header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectHeader().valueEquals("Content-Security-Policy",
                        "default-src 'none'; frame-ancestors 'none'")
                // Spring secure defaults must remain (NOT disabled).
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("X-Frame-Options", "DENY")
                // No-document BFF behind the TLS edge: HSTS / Permissions-Policy omitted.
                .expectHeader().doesNotExist("Strict-Transport-Security")
                .expectHeader().doesNotExist("Permissions-Policy");
    }

    // ── hardened headers PRESENT even on the unauthenticated 401 ──────────────

    @Test
    void hardenedHeaders_presentOnUnauthenticated401() {
        client.get().uri("/bff/mod/reports")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals("Content-Security-Policy",
                        "default-src 'none'; frame-ancestors 'none'")
                .expectHeader().valueEquals("X-Content-Type-Options", "nosniff")
                .expectHeader().valueEquals("X-Frame-Options", "DENY")
                .expectHeader().doesNotExist("Strict-Transport-Security");
    }

    // ── fail-closed floor unchanged (header hardening is additive) ────────────

    @Test
    void anonymous_stillDeniedOn_arbitraryGatedPath() {
        // anyExchange().authenticated() — the deny-by-default floor still 401s anonymous.
        client.get().uri("/api/whatever").exchange().expectStatus().isUnauthorized();
    }

    /** Maps the paths the slice exercises so an ALLOWED request resolves to 200. */
    @RestController
    static class ProbeController {
        @RequestMapping({"/bff/mod/reports", "/api/whatever"})
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }
}
