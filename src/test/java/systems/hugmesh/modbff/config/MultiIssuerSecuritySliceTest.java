package systems.hugmesh.modbff.config;

import systems.hugmesh.commons.config.TenancyResourceServerConfig;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.modbff.testsupport.TestIssuer;

import java.util.List;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * KEYSTONE multi-issuer security-slice for the moderator BFF — replicated VERBATIM
 * from the hugmesh-gateway reference pattern (PR #34, branch
 * {@code test/security-slice-keystone}; see {@code docs/testing/MULTI-ISSUER-SLICE.md}).
 *
 * <p>This drives a {@link WebTestClient} against the REAL
 * {@link SecurityConfig#filterChain} (the prod {@code @Profile("!dev & !test")} chain)
 * wired with the REAL {@link TenancyResourceServerConfig#tenantAuthManagerResolver()}
 * (multi-issuer ENABLED). Each brand is backed by a {@link TestIssuer} — an in-process
 * JWKS + OIDC-discovery server on {@code 127.0.0.1} — so {@code fromIssuerLocation}
 * validates real RSA-signed tokens with NO network and NO live Casdoor. Deterministic.
 *
 * <p>The three keystones (per {@code docs/testing/MULTI-ISSUER-SLICE.md}):
 * <ol>
 *   <li><b>(a) trusted issuer resolves + authority emitted</b> — a brand-X token
 *       resolves to brand-X's manager, authenticates, and {@code DOMAIN_brandx} is
 *       emitted (the per-issuer Casdoor converter is wired);</li>
 *   <li><b>(b) UNKNOWN issuer -&gt; 401 fail-closed</b> — a well-formed, correctly
 *       signed token from an issuer NOT in {@code app.tenancy.issuers} gets NO manager
 *       (resolver returns {@code Mono.empty()}) and 401s — NEVER a default-accept;</li>
 *   <li><b>(c) cross-brand isolation</b> — a brand-Y token is scoped to brand-Y and can
 *       NEVER become brand-X (no {@code DOMAIN_brandx}).</li>
 * </ol>
 *
 * <p>Categories per the comprehensive test standard: (a) is USER-SITUATIONAL (a brand's
 * own token on its own surface); (b)+(c) are CROSS-USER DENY (the tenant-isolation
 * boundary — an unknown / wrong-brand issuer can never cross in).
 *
 * <p>NOTE on the gated surface: the moderator BFF's only role-gated path is
 * {@code /bff/mod/**} ({@code hasAnyRole('MOD','ADMIN','SUPERADMIN')}); everything else
 * floors to {@code authenticated()}. The {@code /whoami} probe below is an arbitrary
 * authenticated path, so it isolates the AUTHENTICATION + authority-emission concern
 * (which manager resolved the token, which authorities it stamped) from the coarse
 * path-gate concern, which {@link SecurityConfigPathGateSliceTest} covers separately.
 */
class MultiIssuerSecuritySliceTest extends SecuritySliceSupport {

    private TestIssuer brandX;
    private TestIssuer brandY;
    private TestIssuer rogue;   // NOT trusted — absent from app.tenancy.issuers
    private WebTestClient client;

    @BeforeEach
    void setUp() {
        brandX = new TestIssuer();
        brandY = new TestIssuer();
        rogue = new TestIssuer();

        // Multi-issuer registry: brand-X + brand-Y trusted; rogue is NOT listed.
        String issuersCsv = brandX.issuerUri() + "=brandx," + brandY.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(brandX.issuerUri(), issuersCsv);
        assertThat(registry.isMultiIssuer())
                .as("two trusted issuers => multi-issuer mode, the swap is taken").isTrue();

        // REAL resolver bean (per-issuer manager + Casdoor converter), built exactly as
        // TenancyResourceServerConfig contributes it. No back-compat jwk-set-uri, so each
        // brand decoder discovers from its own issuer (the in-process server).
        TenancyResourceServerConfig tenancy = new TenancyResourceServerConfig(registry, "", "", false, 600000L);
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                systems.hugmesh.commons.config.TenancyResolvers.tenantResolver(tenancy);

        client = sliceClient(registry, provider(resolver), new AuthoritiesController());
    }

    @AfterEach
    void tearDown() {
        brandX.close();
        brandY.close();
        rogue.close();
    }

    // ── (a) trusted issuer resolves + DOMAIN_<x> authority emitted ────────────

    @Test
    void userSituational_brandXToken_authenticates_andEmitsDomainXAuthority() {
        String token = brandX.mint("mod-x", List.of("mod"));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .value(body -> assertThat(body)
                        .as("brand-X token resolves to brand-X's manager and is stamped DOMAIN_brandx")
                        .contains("DOMAIN_brandx")
                        // the Casdoor converter ran: roles -> ROLE_, floor ROLE_USER
                        .contains("ROLE_MOD")
                        .contains("ROLE_USER")
                        // and NOT the other brand's domain
                        .doesNotContain("DOMAIN_brandy"));
    }

    @Test
    void multiUser_brandYToken_authenticates_andEmitsDomainYAuthority() {
        String token = brandY.mint("mod-y", List.of("admin"));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .value(body -> assertThat(body)
                        .contains("DOMAIN_brandy")
                        .contains("ROLE_ADMIN")
                        .doesNotContain("DOMAIN_brandx"));
    }

    // ── (b) UNKNOWN issuer -> 401 fail-closed ─────────────────────────────────

    @Test
    void crossUser_unknownIssuerToken_is401_failClosed_neverDefaultAccept() {
        // The rogue issuer is a perfectly valid, well-formed, correctly-signed JWT —
        // it is just NOT in app.tenancy.issuers. The per-issuer resolver returns
        // Mono.empty() for it, which the JwtIssuerReactiveAuthenticationManagerResolver
        // surfaces as an authentication failure: 401. There is NO default manager that
        // would let an unlisted issuer through. A future refactor that introduced a
        // default-accept (or routed an unknown iss to brand-X's manager) turns this red.
        String token = rogue.mint("attacker", List.of("mod", "admin", "superadmin"));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void crossUser_garbageBearer_is401() {
        // A non-JWT bearer also fails closed (no issuer to resolve).
        client.get().uri("/whoami")
                .header("Authorization", "Bearer not-a-jwt")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── (c) cross-brand isolation — brand-Y token never becomes brand-X ───────

    @Test
    void crossUser_brandYToken_cannotImpersonateBrandX() {
        // A brand-Y-issued token carries brand-Y's `iss` and is signed by brand-Y's
        // key. It validates ONLY against brand-Y's manager. It can NEVER authenticate
        // AS brand-X: there is no path by which presenting a brand-Y token yields a
        // DOMAIN_brandx authority. We prove the positive (it authenticates as brand-Y,
        // never brand-X) — the isolation boundary holds in both directions.
        String token = brandY.mint("mod-y", List.of("mod"));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .value(body -> assertThat(body)
                        .as("a brand-Y token is scoped to brand-Y; it can NEVER become brand-X")
                        .contains("DOMAIN_brandy")
                        .doesNotContain("DOMAIN_brandx"));
    }

    @Test
    void crossUser_permissionsCannotForgeReservedAuthorities() {
        // Authority-injection defense (CasdoorAuthorities.RESERVED_PREFIXES): a brand-Y
        // token cannot smuggle a forged DOMAIN_brandx tenant scope nor a ROLE_SUPERADMIN
        // super-role via the verbatim `permissions` claim. Both reserved-prefix entries
        // are dropped; only the issuer-derived DOMAIN_brandy survives.
        String token = brandY.mintWithClaims("attacker", java.util.Map.of(
                "roles", List.of(java.util.Map.of("name", "mod")),
                "permissions", List.of("DOMAIN_brandx", "ROLE_SUPERADMIN", "urn:mod:legit")));
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .value(body -> assertThat(body)
                        .as("reserved-prefix permission entries are dropped; issuer-derived DOMAIN wins")
                        .contains("DOMAIN_brandy")
                        .contains("urn:mod:legit")     // a non-reserved permission survives
                        .doesNotContain("DOMAIN_brandx")
                        .doesNotContain("ROLE_SUPERADMIN"));
    }

    @Test
    void crossUser_tamperedSignature_is401() {
        // A brand-X token whose signature is corrupted fails brand-X's manager
        // validation -> 401 (not silently accepted). Same fail-closed posture.
        String token = brandX.mint("mod-x", List.of("mod"));
        String tampered = token.substring(0, token.length() - 4) + "AAAA";
        client.get().uri("/whoami")
                .header("Authorization", "Bearer " + tampered)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    /** Echoes the authenticated principal's authorities — the simplest probe that
     *  proves which manager resolved the token and which authorities it emitted. */
    @RestController
    static class AuthoritiesController {
        @GetMapping("/whoami")
        Mono<String> whoami() {
            return ReactiveSecurityContextHolder.getContext()
                    .map(ctx -> ctx.getAuthentication().getAuthorities().stream()
                            .map(Object::toString)
                            .collect(Collectors.joining(",")))
                    .defaultIfEmpty("ANONYMOUS");
        }
    }
}
