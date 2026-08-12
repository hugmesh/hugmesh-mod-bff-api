package net.hugmesh.modbff.config;

import net.hugmesh.commons.config.TenancyResourceServerConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.security.Roles;
import net.hugmesh.modbff.testsupport.Wave2TestIssuer;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * MULTI-ISSUER SWAP at the FILTER CHAIN — the real {@link SecurityConfig#filterChain}
 * (prod {@code @Profile("!dev & !test")}) wired with the real
 * {@link TenancyResourceServerConfig} per-issuer resolver, driven by two independent
 * in-process {@link Wave2TestIssuer}s (brand X / brand Y). This proves at the HTTP
 * boundary what the converter + registry unit tests only prove in isolation:
 *
 * <ul>
 *   <li><b>Token from brand X resolves the brand-X domain</b> — a token minted by
 *       issuer X validates against X's per-issuer manager and the converter stamps
 *       {@code DOMAIN_brandx}; the probe echoes the issuer-derived domain
 *       ({@link Roles#domainOf(Authentication)}), so the brand is taken from the
 *       VALIDATED issuer, never a request param/body.</li>
 *   <li><b>Token from brand Y resolves the brand-Y domain</b> — the swap distinguishes
 *       the two trusted issuers; X's domain never leaks onto Y's token.</li>
 *   <li><b>Unknown issuer → 401</b> — a cryptographically valid token from an issuer
 *       NOT in {@code app.tenancy.issuers} gets NO manager from the resolver and 401s,
 *       fail-closed, before any authority is emitted (the A07 fail-closed boundary).</li>
 *   <li><b>Cross-brand signature → 401</b> — a token claiming brand-X's {@code iss} but
 *       signed with brand-Y's key fails X's manager's signature validation (401): the
 *       per-issuer JWK isolation, not merely an iss-string allowlist.</li>
 * </ul>
 *
 * <p>The two issuers make {@link DomainRegistry#isMultiIssuer()} true, so
 * {@link SecurityConfig} takes the per-issuer {@code authenticationManagerResolver}
 * swap (NOT the single-issuer {@code o.jwt(...)} path) — this is the seam this slice
 * exercises end-to-end.
 */
class Wave2MultiIssuerSwapSliceTest extends Wave2SecuritySliceSupport {

    private Wave2TestIssuer brandX;
    private Wave2TestIssuer brandY;
    private Wave2TestIssuer untrusted;   // a 3rd, valid-but-NOT-configured issuer
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        brandX = new Wave2TestIssuer();
        brandY = new Wave2TestIssuer();
        untrusted = new Wave2TestIssuer();
        // Two trusted brands => isMultiIssuer() true => SecurityConfig takes the swap.
        // 'untrusted' is deliberately ABSENT from this CSV.
        String issuersCsv = brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(brandX.issuerUri(), issuersCsv);
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "", false, 600000L);
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                net.hugmesh.commons.config.TenancyResolvers.tenantResolver(tenancy);
        client = sliceClient(registry, provider(resolver), new WhoAmIController());
    }

    @AfterEach
    void tearDown() {
        brandX.close();
        brandY.close();
        untrusted.close();
    }

    private WebTestClient.ResponseSpec getWhoAmI(String bearer) {
        return client.get().uri("/bff/mod/whoami")
                .header("Authorization", "Bearer " + bearer)
                .exchange();
    }

    // ── Token from brand X resolves the brand-X domain (issuer-derived) ───────
    @Test
    void brandXToken_resolvesBrandXDomain_fromValidatedIssuer() {
        String token = brandX.mint("mod-x", List.of("mod"));
        getWhoAmI(token)
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.domain").isEqualTo("brandx")
                .jsonPath("$.name").isEqualTo("mod-x");
    }

    // ── Token from brand Y resolves the brand-Y domain (no cross-brand leak) ──
    @Test
    void brandYToken_resolvesBrandYDomain_notBrandX() {
        String token = brandY.mint("mod-y", List.of("mod"));
        getWhoAmI(token)
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.domain").isEqualTo("brandy");
    }

    // ── The two swap to DIFFERENT managers — same subject string, different brand ─
    @Test
    void sameSubjectTwoBrands_resolveDistinctDomains() {
        // Two brands' Casdoor can mint the SAME subject string; the domain is the
        // issuer-derived discriminator, so the same "alice" lands in two distinct tenants.
        getWhoAmI(brandX.mint("alice", List.of("mod")))
                .expectStatus().isOk().expectBody().jsonPath("$.domain").isEqualTo("brandx");
        getWhoAmI(brandY.mint("alice", List.of("mod")))
                .expectStatus().isOk().expectBody().jsonPath("$.domain").isEqualTo("brandy");
    }

    // ── UNKNOWN issuer → 401 (fail-closed) ────────────────────────────────────
    @Test
    void unknownIssuerToken_is401_failClosed() {
        // 'untrusted' is a perfectly valid, self-consistent issuer (its own discovery +
        // JWKS) but is NOT in app.tenancy.issuers — the resolver yields NO manager, so
        // the request 401s before any authority/domain is emitted. NEVER 200, never 403.
        String token = untrusted.mint("intruder", List.of("admin", "superadmin"));
        getWhoAmI(token).expectStatus().isUnauthorized();
    }

    // ── Cross-brand SIGNATURE → 401 (per-issuer JWK isolation) ────────────────
    @Test
    void tokenClaimingBrandXIss_butSignedByBrandY_is401() {
        // Forge the iss to brand-X but sign with brand-Y's key. The resolver routes on
        // the iss claim to brand-X's manager, whose decoder fetches brand-X's JWKS — the
        // brand-Y signature fails validation → 401. This is signature isolation, not a
        // mere iss-string allowlist.
        String forged = brandY.mintWithClaims("intruder",
                Map.of("iss", brandX.issuerUri(), "roles", List.of(Map.of("name", "admin"))));
        getWhoAmI(forged).expectStatus().isUnauthorized();
    }

    // ── Anonymous → 401 at the authenticated() floor ──────────────────────────
    @Test
    void anonymous_is401() {
        client.get().uri("/bff/mod/whoami").exchange().expectStatus().isUnauthorized();
    }

    /**
     * Echoes the issuer-derived domain + subject the security chain resolved, so the
     * test asserts the brand was taken from the VALIDATED token (never a request input).
     * Mapped under {@code /bff/mod/**} so the MOD floor lets an authenticated MOD/ADMIN
     * through to the echo.
     */
    @RestController
    static class WhoAmIController {
        @GetMapping("/bff/mod/whoami")
        Mono<Map<String, Object>> whoami(Authentication auth) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("name", auth == null ? null : auth.getName());
            out.put("domain", Roles.domainOf(auth));   // DOMAIN_<x> off the validated issuer
            return Mono.just(out);
        }
    }
}
