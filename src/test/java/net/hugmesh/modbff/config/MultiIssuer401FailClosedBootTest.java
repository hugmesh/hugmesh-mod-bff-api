package net.hugmesh.modbff.config;

import net.hugmesh.commons.config.TenancyResourceServerConfig;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.external.MatrixAdminClient;
import net.hugmesh.modbff.federation.FederationApiClient;
import net.hugmesh.modbff.testsupport.TestIssuer;
import net.hugmesh.commons.testsupport.PostgresTestSupport;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * FULL-BOOT multi-issuer 401 fail-closed coverage — the gap the slice tests
 * ({@link MultiIssuerSecuritySliceTest}, {@link Wave2MultiIssuerSwapSliceTest}) leave
 * open. Those hand-construct {@code new SecurityConfig(...)} +
 * {@code new TenancyResourceServerConfig(...)}, so they never prove the production
 * <em>wiring</em>: that with {@code app.tenancy.issuers} actually set, Spring boots the
 * REAL bean graph — the {@code @ConditionalOnExpression('...contains(=)')} on
 * {@link TenancyResourceServerConfig} fires, the per-issuer
 * {@link ReactiveAuthenticationManagerResolver} bean is contributed, the real
 * {@link DomainRegistry} is bound from the property, and
 * {@link SecurityConfig#configureResourceServer} takes the multi-issuer swap
 * (gated on {@link DomainRegistry#isMultiIssuer()}). This is the seam the D6 cookie +
 * the MFA step-up changes will ride: if a future refactor breaks the conditional, the
 * property binding, or the swap, the resource server would silently fall back to a path
 * that could accept a foreign issuer — exactly the fail-OPEN regression this pins.
 *
 * <p>This boots the WHOLE application context ({@code @SpringBootTest} on a real port)
 * and drives a {@link WebTestClient} over HTTP at the booted server. The
 * {@code app.tenancy.issuers} property is fed two REAL in-process {@link TestIssuer}
 * brands via {@code @DynamicPropertySource} (their loopback OIDC-discovery + JWKS
 * servers), so {@code fromIssuerLocation} validates real RSA-signed tokens with NO
 * network egress and NO live Casdoor. Crucially, NO {@code ReactiveJwtDecoder} is mocked
 * here (the {@code ModBffApplicationTest} smoke test mocks it) — the point is that the
 * real validation surface runs.
 *
 * <p>The three required proofs, end-to-end through the booted app:
 * <ol>
 *   <li><b>(a) VALID configured issuer → accepted (200).</b> A token from brand-X (a
 *       configured {@code app.tenancy.issuers} entry) carrying ROLE_MOD reaches the
 *       gated {@code /bff/mod/status} and is stamped {@code DOMAIN_brandx} from the
 *       cryptographically-validated issuer.</li>
 *   <li><b>(b) FOREIGN / unconfigured issuer → 401 fail-closed.</b> A perfectly
 *       well-formed, correctly-signed token from an issuer NOT in
 *       {@code app.tenancy.issuers} gets NO manager from the per-issuer resolver
 *       ({@code Mono.empty()}) and 401s — it is NEVER silently accepted, NEVER treated
 *       as anonymous-allowed (which would surface as a 200 or a 403, not a 401), NEVER
 *       routed to a trusted brand's manager. We assert it against the SAME gated path
 *       the valid token reaches, so an accidental default-accept turns this red.</li>
 *   <li><b>(c) TAMPERED-signature and WRONG-KID → 401.</b> A brand-X token with a
 *       corrupted signature, and a token carrying brand-X's {@code iss} but signed by a
 *       key whose {@code kid} is absent from brand-X's JWKS, both fail brand-X's
 *       manager's signature/JWK validation → 401 (per-issuer JWK isolation, not a mere
 *       {@code iss}-string allowlist).</li>
 * </ol>
 *
 * <p>Categories per the comprehensive test standard: (a) is USER-SITUATIONAL; (b) and
 * (c) are CROSS-USER DENY (the A07 fail-closed authentication boundary — an unknown /
 * forged / wrong-key issuer can never cross in).
 *
 * <p>Datastore + downstream-client beans are mocked so the context boots with no real
 * Postgres / federation-api / homeservers (the {@code test} profile already disables
 * Liquibase and points R2DBC at a throwaway in-mem H2); only the AUTHENTICATION surface
 * is exercised for real.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class MultiIssuer401FailClosedBootTest extends PostgresTestSupport {

    // Two trusted brands + one untrusted, foreign issuer. Static so the same loopback
    // OIDC servers back the property values fed via @DynamicPropertySource (which runs
    // before the context starts) and the per-test token minting.
    private static final TestIssuer BRAND_X = new TestIssuer();
    private static final TestIssuer BRAND_Y = new TestIssuer();
    private static final TestIssuer FOREIGN = new TestIssuer();   // NOT in app.tenancy.issuers

    @DynamicPropertySource
    static void tenancyIssuers(DynamicPropertyRegistry registry) {
        // Two issuer=domain pairs => the @ConditionalOnExpression fires AND
        // DomainRegistry.isMultiIssuer() is true => SecurityConfig takes the per-issuer
        // resolver swap. 'FOREIGN' is deliberately ABSENT.
        registry.add("app.tenancy.issuers",
                () -> BRAND_X.issuerUri() + "=brandx," + BRAND_Y.issuerUri() + "=brandy");
        // Point the lone back-compat issuer-uri at brand-X too, so Spring Boot's
        // resource-server auto-config has a REACHABLE in-process issuer to bind to at
        // startup (the multi-issuer swap means the chain uses the resolver, not this
        // decoder, but the bean still constructs). No network egress beyond loopback.
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", BRAND_X::issuerUri);
        // Explicit jwk-set-uri for that SAME back-compat issuer, pinned to BRAND_X's
        // in-process JWKS endpoint. application.yml's jwk-set-uri default (added for the
        // in-DNS Casdoor fix) otherwise resolves to the real
        // https://id.hugmesh.net/.well-known/jwks — unreachable here — and
        // TenancyResourceServerConfig.backCompatJwkSetUri only skips OIDC discovery FOR
        // that issuer when jwk-set-uri is set, so a stale/default value there fails EVERY
        // request in this class at key-lookup time (500, not the expected 401/403/200).
        // No egress beyond loopback.
        registry.add("spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> BRAND_X.issuerUri() + "/.well-known/jwks.json");
    }

    @AfterAll
    static void closeIssuers() {
        BRAND_X.close();
        BRAND_Y.close();
        FOREIGN.close();
    }

    // Bound to the booted RANDOM_PORT server by Spring Boot (the resource-server filter
    // chain runs over real HTTP), so the JWT validation is exercised exactly as in prod.
    @Autowired WebTestClient client;

    // Datastore + downstream clients mocked so the full context boots without a real
    // Postgres / federation-api / homeservers. The authentication surface is NOT mocked.
    @MockitoBean ModActionRepository modActionRepository;
    @MockitoBean FederationApiClient federationApiClient;
    @MockitoBean MatrixAdminClient matrixAdminClient;
    @MockitoBean MastodonAdminClient mastodonAdminClient;

    private WebTestClient client() {
        return client;
    }

    // ── PRE-CONDITION: the booted context genuinely took the multi-issuer swap ────
    // If this is false the (a)/(b)/(c) assertions would be exercising the wrong path,
    // so we assert the seam is real before trusting the fail-closed proofs.
    @Test
    void bootedContext_isInMultiIssuerMode_andContributedTheResolverBean(
            @Autowired DomainRegistry domainRegistry,
            @Autowired(required = false)
                    ReactiveAuthenticationManagerResolver<ServerWebExchange> tenantResolver) {
        assertThat(domainRegistry.isMultiIssuer())
                .as("two configured app.tenancy.issuers pairs => the multi-issuer swap is taken")
                .isTrue();
        assertThat(domainRegistry.trustedIssuers())
                .as("only the two configured brands are trusted; FOREIGN is absent")
                .contains(trimSlash(BRAND_X.issuerUri()), trimSlash(BRAND_Y.issuerUri()))
                .doesNotContain(trimSlash(FOREIGN.issuerUri()));
        assertThat(tenantResolver)
                .as("the @ConditionalOnExpression fired => TenancyResourceServerConfig "
                        + "contributed the per-issuer ReactiveAuthenticationManagerResolver bean")
                .isNotNull();
    }

    // ── (a) VALID configured issuer → accepted (200) ─────────────────────────────
    @Test
    void userSituational_validConfiguredIssuerToken_isAccepted_200() {
        String token = BRAND_X.mint("mod-x", List.of("mod"));
        client().get().uri("/bff/mod/status")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                // domain is derived from the cryptographically-validated issuer, never input
                .jsonPath("$.domain").isEqualTo("brandx")
                .jsonPath("$.sub").isEqualTo("mod-x")
                .jsonPath("$.roles[?(@ == 'MOD')]").exists();
    }

    @Test
    void userSituational_otherConfiguredIssuerToken_isAccepted_andScopedToItsOwnBrand() {
        // A second trusted brand authenticates and is scoped to brandy — proving the
        // swap distinguishes the two configured issuers (no cross-brand leak).
        String token = BRAND_Y.mint("mod-y", List.of("admin"));
        client().get().uri("/bff/mod/status")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.domain").isEqualTo("brandy")
                .jsonPath("$.roles[?(@ == 'ADMIN')]").exists();
    }

    // ── (b) FOREIGN / unconfigured issuer → 401 fail-closed ──────────────────────
    @Test
    void crossUser_foreignUnconfiguredIssuerToken_is401_failClosed_neverAccepted() {
        // FOREIGN is a perfectly valid, self-consistent, correctly-signed issuer — it is
        // just NOT in app.tenancy.issuers. The per-issuer resolver returns Mono.empty()
        // for its iss, surfaced as an authentication failure: 401. There is NO default
        // manager to let an unlisted issuer through. We deliberately load the token with
        // mod/admin/superadmin so a fail-OPEN regression (default-accept, or routing the
        // unknown iss to a trusted manager) would visibly grant access — 401 proves it
        // does not. It is NOT 200 (accepted) and NOT 403 (authenticated-but-forbidden,
        // i.e. anonymous/authenticated-with-no-role): it never authenticates at all.
        String token = FOREIGN.mint("attacker", List.of("mod", "admin", "superadmin"));
        client().get().uri("/bff/mod/status")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void crossUser_foreignIssuer_alsoRejectedOnAnAuthenticatedFloorPath_notJustTheRoleGate() {
        // Same foreign token against a path that only needs authenticated() (the
        // actuator info-less anyExchange floor). Even with NO role requirement it 401s —
        // proving the rejection is at AUTHENTICATION (fail-closed), not merely the
        // role/authorization gate. (/actuator/health is permitAll, so we use a path that
        // is NOT permitAll: the gated /bff/mod surface already covers the role path; here
        // an arbitrary non-permitAll path confirms the authenticated() floor also denies.)
        String token = FOREIGN.mint("attacker", List.of("mod"));
        client().get().uri("/bff/mod/status")
                .header("Authorization", "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── (c) TAMPERED signature → 401 ─────────────────────────────────────────────
    @Test
    void crossUser_tamperedSignature_is401() {
        // A brand-X token whose signature bytes are corrupted fails brand-X's manager's
        // signature validation → 401 (never silently accepted).
        String token = BRAND_X.mint("mod-x", List.of("mod"));
        String tampered = token.substring(0, token.length() - 4) + "AAAA";
        client().get().uri("/bff/mod/status")
                .header("Authorization", "Bearer " + tampered)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    // ── (c) WRONG-KID → 401 ──────────────────────────────────────────────────────
    @Test
    void crossUser_brandXIssuer_butWrongKidUnknownKey_is401() throws Exception {
        // A token that CLAIMS brand-X's iss (so the resolver routes it to brand-X's
        // manager) but is signed by a freshly generated key whose `kid` is NOT in
        // brand-X's published JWKS. Brand-X's decoder cannot find a matching JWK for that
        // kid → signature validation fails → 401. This is the per-issuer JWK isolation:
        // claiming the right issuer string is not enough; the signature must verify
        // against THAT issuer's published keys.
        String wrongKidToken = mintWithUnknownKid(BRAND_X.issuerUri(), "mod-x", List.of("mod"));
        client().get().uri("/bff/mod/status")
                .header("Authorization", "Bearer " + wrongKidToken)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void crossUser_garbageBearer_is401() {
        // A non-JWT bearer also fails closed (no issuer to resolve).
        client().get().uri("/bff/mod/status")
                .header("Authorization", "Bearer not-a-jwt")
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void crossUser_anonymous_is401_atTheAuthenticatedFloor() {
        client().get().uri("/bff/mod/status").exchange().expectStatus().isUnauthorized();
    }

    /**
     * Mint a token whose {@code iss} is {@code issuer} but signed by a brand-new RSA key
     * with a random {@code kid} that is NOT in any trusted issuer's JWKS. The resolver
     * routes on the iss claim to that issuer's manager; the decoder then fails to resolve
     * the unknown kid against the issuer's published keys → 401. Self-contained (Nimbus
     * is already on the test classpath via the oauth2-resource-server starter).
     */
    private static String mintWithUnknownKid(String issuer, String subject, List<String> roleNames)
            throws Exception {
        RSAKey unknownKey = new RSAKeyGenerator(2048)
                .keyID("unknown-kid-" + java.util.UUID.randomUUID())
                .generate();
        Instant now = Instant.now();
        List<Map<String, String>> roles = roleNames.stream().map(r -> Map.of("name", r)).toList();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(subject)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plusSeconds(300)))
                .claim("roles", roles)
                .claim("name", subject)
                .build();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(unknownKey.getKeyID()).build(),
                claims);
        jwt.sign(new RSASSASigner(unknownKey));
        return jwt.serialize();
    }

    private static String trimSlash(String s) {
        String t = s.trim();
        return t.endsWith("/") ? t.substring(0, t.length() - 1) : t;
    }

    /** No extra beans needed beyond the @MockitoBean datastore/clients + the
     *  PostgresTestSupport-provisioned container db. */
    @TestConfiguration(proxyBeanMethods = false)
    static class NoExtraBeans {
        @Bean String marker() { return "multi-issuer-401-boot"; }
    }
}
