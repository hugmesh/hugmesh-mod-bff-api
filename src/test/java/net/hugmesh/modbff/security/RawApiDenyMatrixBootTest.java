package net.hugmesh.modbff.security;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.modbff.admin.AdminDomainLockClient;
import net.hugmesh.modbff.admin.AdminSuspensionClient;
import net.hugmesh.modbff.admin.SuspensionOutcome;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.external.MatrixAdminClient;
import net.hugmesh.modbff.federation.FederationApiClient;
import net.hugmesh.modbff.testsupport.TestIssuer;
import net.hugmesh.commons.testsupport.PostgresTestSupport;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * RAW-API-DENY negative security matrix for the moderator BFF — the FULL-BOOT analog of
 * the federation-api {@code CrossDomainWriteIsolationTest} + {@code MultiIssuerSecuritySliceTest},
 * built on THIS repo's gold exemplars ({@code MultiIssuer401FailClosedBootTest} +
 * {@code ModAuditDomainScopeControllerTest}).
 *
 * <h2>What this proves (and how it is mutation-resistant)</h2>
 * Every test asserts that a RESTRICTED caller hitting a moderation WRITE endpoint
 * ({@code /bff/mod/ban}, {@code /lift}, {@code /block}, {@code /domain-lock} — the
 * "decide" surface — plus {@code /moderation} recommend/refer) is DENIED with the
 * authority-table status (401 / 403) AND that the action DID NOT take effect. The
 * "did-not-take-effect" half is the load-bearing, mutation-resistant part: this boots
 * the WHOLE application with a REAL {@link ModActionRepository} over a REAL
 * Testcontainers-Postgres store that Liquibase applies the production changelog over
 * (this class {@code extends PostgresTestSupport}), and a REAL {@code ModService} carrying its
 * real guard chain. After EVERY denied call we RE-READ the audit table
 * ({@link ModActionRepository#list()}) and assert it is still EMPTY — so an authz
 * fail-open that let the write through would have left an audit row and turned the test
 * red. The only mocked beans are the DOWNSTREAM write clients
 * ({@link AdminSuspensionClient} / {@link AdminDomainLockClient} / {@link FederationApiClient}),
 * stubbed to SUCCEED — meaning if a guard ever leaked, the write would genuinely land,
 * making the empty-DB assertion a true negative-control rather than a vacuous one.
 *
 * <h2>Real RS256 tokens, no network, no live Casdoor</h2>
 * Two trusted brands ({@code brandx}, {@code brandy}) + one FOREIGN issuer are backed by
 * in-process {@link TestIssuer} JWKS/OIDC servers on loopback, fed to
 * {@code app.tenancy.issuers} via {@code @DynamicPropertySource} so the booted context
 * takes the multi-issuer per-issuer-manager swap and validates real RSA-signed tokens.
 * Tokens are minted in-test with an arbitrary {@code sub} / {@code roles} / issuer —
 * NO secrets, NO checked-in keys.
 *
 * <h2>Negative classes covered (authority = SecurityConfig path table + @PreAuthorize)</h2>
 * <ul>
 *   <li><b>ROLE_USER → 403</b> on the whole {@code /bff/mod/**} write surface — the
 *       chain {@code hasAnyRole('MOD','ADMIN','SUPERADMIN')} path gate denies before any
 *       controller method runs (privilege-escalation deny).</li>
 *   <li><b>Cross-tenant (cross-domain BOLA/BFLA) → 403</b> — a brand-Y MOD trying to
 *       ban / domain-lock a brand-X target: {@code ModService.guardSameTenant} cannot
 *       PROVE the target is in the caller's brand (Casdoor role-seam off in {@code test}
 *       → {@code belongsToDomain} fail-closed) so the write is denied BEFORE any audit
 *       row or downstream write.</li>
 *   <li><b>SUPERADMIN reaches the mod write surface via the role hierarchy (ALLOW
 *       control, cross-tier)</b> — the cross-domain infra control plane is a strict
 *       superset of ADMIN ({@code ROLE_SUPERADMIN > ROLE_ADMIN}, PR #52), so a SUPERADMIN
 *       PASSES both the chain path gate AND the method {@code @PreAuthorize("hasAnyRole(
 *       'MOD','ADMIN')")} on the ENFORCE writes, and the write PROCEEDS (202 +
 *       audit row) — and being UNSCOPED it bypasses the same-tenant proof
 *       ({@code ModService.guardSameTenant}). This is the HTTP-layer analog of
 *       {@code ModServiceTest.ban_superadminCrossBrand_bypassesTenantGuard_andWriteProceeds}
 *       and the {@code Wave2RoleMatrixEndToEndSliceTest} superadmin-via-hierarchy guard.
 *       (Earlier this class asserted superadmin was DENIED here — that predated #52's
 *       hierarchy and is now corrected; the deny matrix proper is ROLE_USER /
 *       cross-tenant / forged-token below.) {@code /bff/mod/block} stays 403 for a
 *       superadmin that lacks the platform role, denied DEEPER by the platform-role
 *       assertion (not {@code @PreAuthorize}).</li>
 *   <li><b>Forged-token / unknown-issuer / anonymous → 401</b> — fail-closed
 *       authentication (a FOREIGN well-signed issuer, a tampered signature, a garbage
 *       bearer, and no token) never authenticates, so it never reaches the write.</li>
 * </ul>
 * Per the comprehensive test standard these are CROSS-USER DENY / cross-tier-DENY cases
 * (plus the SUPERADMIN cross-tier ALLOW control).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class RawApiDenyMatrixBootTest extends PostgresTestSupport {

    // Two trusted brands + one untrusted, foreign issuer (NOT in app.tenancy.issuers).
    private static final TestIssuer BRAND_X = new TestIssuer();
    private static final TestIssuer BRAND_Y = new TestIssuer();
    private static final TestIssuer FOREIGN = new TestIssuer();

    @DynamicPropertySource
    static void tenancyIssuers(DynamicPropertyRegistry registry) {
        // The shared `test` profile disables Liquibase; this test re-reads the REAL
        // audit table over the per-class Postgres the base wires, so re-enable it.
        registry.add("spring.liquibase.enabled", () -> "true");
        registry.add("app.tenancy.issuers",
                () -> BRAND_X.issuerUri() + "=brandx," + BRAND_Y.issuerUri() + "=brandy");
        // Lone back-compat issuer-uri pointed at a reachable in-process brand so the
        // resource-server auto-config bean still constructs at startup (the swap uses the
        // resolver, not this decoder). No egress beyond loopback.
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", BRAND_X::issuerUri);
        // Explicit jwk-set-uri for that SAME back-compat issuer, pinned to BRAND_X's
        // in-process JWKS endpoint. application.yml's app.test-seed-adjacent jwk-set-uri
        // default (added for the in-DNS Casdoor fix) otherwise resolves to the real
        // https://id.hugmesh.systems/.well-known/jwks — unreachable here — and
        // TenancyResourceServerConfig.backCompatJwkSetUri only skips OIDC discovery FOR
        // that issuer when jwk-set-uri is set, so a stale/default value there fails EVERY
        // request in this class (not just brandx's) at key-lookup time (500, not 401/403).
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

    // Bound to the booted RANDOM_PORT server so the real resource-server filter chain +
    // @PreAuthorize method security run over real HTTP exactly as in prod.
    @Autowired WebTestClient client;

    // REAL repository over the REAL H2 (Liquibase) schema — the mutation-resistant
    // re-read target. A SPY so we can ALSO assert the write-record method is NEVER called
    // (belt-and-suspenders alongside the empty-DB re-read).
    @MockitoSpyBean ModActionRepository audit;

    // DOWNSTREAM write clients mocked to SUCCEED: if a guard ever leaked, the write would
    // genuinely land, so the empty-DB assertion is a real negative control, not vacuous.
    @MockitoBean AdminSuspensionClient suspensions;
    @MockitoBean AdminDomainLockClient domainLocks;
    @MockitoBean FederationApiClient federation;
    @MockitoBean MatrixAdminClient matrix;
    @MockitoBean MastodonAdminClient mastodon;

    // Direct SQL handle to RESET the per-class shared Postgres between tests — the
    // SUPERADMIN ALLOW cases legitimately WRITE an audit row, so without a per-test
    // truncate those rows would leak into the deny cases' empty-table assertion (the
    // same pattern the audit-repo boot tests use).
    @Autowired DatabaseClient db;

    @BeforeEach
    void resetAuditTableAndStubDownstreamWritesToSucceed() {
        // Start every test from an empty mod_action so assertNothingWritten() / one-row
        // assertions are exact across the shared per-class container.
        db.sql("DELETE FROM mod_action").fetch().rowsUpdated().block();
        // lenient(): not every test exercises every client; these stubs only matter on the
        // path where the write WOULD reach them.
        lenient().when(suspensions.suspend(any(), any(), any(), any()))
                .thenReturn(Mono.just(SuspensionOutcome.PENDING));
        lenient().when(suspensions.suspend(any(), any(), any(), any(), any(), org.mockito.ArgumentMatchers.anyBoolean()))
                .thenReturn(Mono.just(SuspensionOutcome.PENDING));
        lenient().when(suspensions.clear(any(), any())).thenReturn(Mono.just(SuspensionOutcome.PENDING));
        lenient().when(domainLocks.lock(any(), any(), any())).thenReturn(Mono.just(SuspensionOutcome.PENDING));
        lenient().when(domainLocks.unlock(any(), any())).thenReturn(Mono.just(SuspensionOutcome.PENDING));
    }

    // ── token helpers ───────────────────────────────────────────────────────────
    private static String userOf(TestIssuer brand, String sub) {
        return brand.mint(sub, List.of("user"));
    }
    private static String modOf(TestIssuer brand, String sub) {
        return brand.mint(sub, List.of("mod"));
    }
    private static String superadminOf(TestIssuer brand, String sub) {
        return brand.mint(sub, List.of("superadmin"));
    }

    private WebTestClient.RequestBodySpec post(String uri, String bearer) {
        return client.post().uri(uri)
                .header("Authorization", "Bearer " + bearer)
                .contentType(MediaType.APPLICATION_JSON);
    }
    private WebTestClient.RequestBodySpec del(String uri, String bearer) {
        return client.method(HttpMethod.DELETE).uri(uri)
                .header("Authorization", "Bearer " + bearer)
                .contentType(MediaType.APPLICATION_JSON);
    }

    /**
     * Re-read the REAL audit table: a denied write must leave it EMPTY (nothing wrote).
     * This is the mutation-resistant check — it observes the actual persisted state over
     * the real Liquibase H2 schema, so it catches a leak through ANY {@code record} /
     * {@code recordBan} overload (no fragile per-overload {@code verify}).
     */
    private void assertNothingWritten() {
        Long rows = audit.list().count().block();
        assertThat(rows)
                .as("a DENIED moderation write must NOT have persisted any mod_action row")
                .isEqualTo(0L);
    }

    // ════════════════════════════════════════════════════════════════════════════
    // (1) ROLE_USER → 403 on the whole write surface  (privilege-escalation DENY)
    //     + verify-never-wrote
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    void roleUser_isForbiddenFromBan_andNothingWrote() {
        post("/bff/mod/ban", userOf(BRAND_X, "alice"))
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"victim\",\"reason\":\"x\"}")
                .exchange().expectStatus().isForbidden();
        assertNothingWritten();
    }

    @Test
    void roleUser_isForbiddenFromLift_andNothingWrote() {
        del("/bff/mod/ban", userOf(BRAND_X, "alice"))
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"victim\"}")
                .exchange().expectStatus().isForbidden();
        assertNothingWritten();
    }

    @Test
    void roleUser_isForbiddenFromBlock_andNothingWrote() {
        post("/bff/mod/block", userOf(BRAND_X, "alice"))
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\",\"target\":\"@v:y\"}")
                .exchange().expectStatus().isForbidden();
        assertNothingWritten();
    }

    @Test
    void roleUser_isForbiddenFromDomainLock_andNothingWrote() {
        post("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/victim", userOf(BRAND_X, "alice"))
                .bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isForbidden();
        assertNothingWritten();
    }

    @Test
    void roleUser_isForbiddenFromRecommend_andNothingWrote() {
        post("/bff/mod/moderation", userOf(BRAND_X, "alice"))
                .bodyValue("{\"kind\":\"user-removal\",\"target\":\"victim\",\"reason\":\"x\"}")
                .exchange().expectStatus().isForbidden();
        assertNothingWritten();
    }

    @Test
    void roleUser_isForbiddenFromRefer_andNothingWrote() {
        post("/bff/mod/moderation/7/refer", userOf(BRAND_X, "alice"))
                .exchange().expectStatus().isForbidden();
        assertNothingWritten();
    }

    // ════════════════════════════════════════════════════════════════════════════
    // (2) CROSS-TENANT (cross-domain BOLA/BFLA) → 403  + verify-never-wrote
    //     A brand-Y MOD cannot ban / domain-lock a target it cannot prove is in brand-Y.
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    void brandYMod_cannotBan_crossTenantTarget_andNothingWrote() {
        // brandY MOD is a fully-authorized moderator (passes path gate + @PreAuthorize),
        // but ModService.guardSameTenant cannot PROVE the target belongs to brandY
        // (Casdoor role-seam OFF in the test profile → belongsToDomain fail-closed),
        // so the cross-tenant write is denied 403 BEFORE any audit row or admin-bff write.
        post("/bff/mod/ban", modOf(BRAND_Y, "mod-y"))
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"brandx-victim\",\"reason\":\"x\"}")
                .exchange().expectStatus().isForbidden();
        assertNothingWritten();
        verify(suspensions, never()).suspend(any(), any(), any(), any());
    }

    @Test
    void brandYMod_cannotDomainLock_crossTenantTarget_andNothingWrote() {
        post("/bff/mod/domain-lock/ROLE_MASTODON_DOMAINLOCKED/brandx-victim", modOf(BRAND_Y, "mod-y"))
                .bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isForbidden();
        assertNothingWritten();
        verify(domainLocks, never()).lock(any(), any(), any());
    }

    @Test
    void brandXMod_cannotLift_crossTenantTarget_andNothingWrote() {
        // lift runs guardSameTenant too — a branded mod may not clear another brand's ban.
        del("/bff/mod/ban", modOf(BRAND_X, "mod-x"))
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"brandy-victim\"}")
                .exchange().expectStatus().isForbidden();
        assertNothingWritten();
        verify(suspensions, never()).clear(any(), any());
    }

    // ════════════════════════════════════════════════════════════════════════════
    // (3) SUPERADMIN REACHES THE MOD WRITE SURFACE VIA THE ROLE HIERARCHY (cross-tier ALLOW)
    //     ROLE_SUPERADMIN > ROLE_ADMIN (PR #52) → a SUPERADMIN satisfies the method
    //     @PreAuthorize("hasAnyRole('MOD','ADMIN')"), and being the UNSCOPED cross-domain
    //     infra control plane it bypasses guardSameTenant → the ban/domain-lock WRITE
    //     PROCEEDS (202 + an audit row). HTTP-layer analog of
    //     ModServiceTest.ban_superadminCrossBrand_bypassesTenantGuard_andWriteProceeds.
    //     (block stays 403 — denied DEEPER by the platform-role assertion, not @PreAuthorize.)
    // ════════════════════════════════════════════════════════════════════════════

    /** A denied write left NOTHING in the audit table; an ALLOWED write leaves exactly one
     *  row — the mutation-POSITIVE control (inverse of {@link #assertNothingWritten()}). */
    private void assertExactlyOneRowWritten() {
        Long rows = audit.list().count().block();
        assertThat(rows)
                .as("an ALLOWED moderation write must have persisted exactly one mod_action row")
                .isEqualTo(1L);
    }

    @Test
    void superadmin_reachesBan_viaHierarchy_andWriteProceeds() {
        post("/bff/mod/ban", superadminOf(BRAND_X, "root"))
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"victim\",\"reason\":\"x\"}")
                .exchange().expectStatus().isAccepted();
        // The write reached the downstream suspension client and persisted an audit row —
        // superadmin is the unscoped infra role, so guardSameTenant is bypassed.
        assertExactlyOneRowWritten();
        verify(suspensions).suspend(any(), any(), any(), any());
    }

    @Test
    void superadmin_reachesDomainLock_viaHierarchy_andWriteProceeds() {
        post("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/victim", superadminOf(BRAND_X, "root"))
                .bodyValue("{\"reason\":\"x\"}")
                .exchange().expectStatus().isAccepted();
        assertExactlyOneRowWritten();
        verify(domainLocks).lock(any(), any(), any());
    }

    @Test
    void superadmin_block_stillDeniedByPlatformRoleGuard_notPreAuthorize_andNothingWrote() {
        // block PASSES @PreAuthorize via the hierarchy, but ModService.block asserts the
        // caller HOLDS the platform role (here ROLE_MATRIX) before any homeserver call — a
        // superadmin-only token lacks it, so the block is denied DEEPER (403) and nothing
        // writes. (This is the platform-role guard, distinct from the @PreAuthorize leg.)
        post("/bff/mod/block", superadminOf(BRAND_X, "root"))
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\",\"target\":\"@v:y\"}")
                .exchange().expectStatus().isForbidden();
        assertNothingWritten();
    }

    @Test
    void superadmin_CAN_readAudit_provingTheWriteGateIsMethodSecurity_notAuthFailure() {
        // CONTROL: the SAME superadmin token is allowed on /bff/mod/audit (@PreAuthorize
        // there lists SUPERADMIN explicitly). Together with the ALLOW cases above this
        // proves the token + auth layer are sound and the gating is purely method-security.
        client.get().uri("/bff/mod/audit")
                .header("Authorization", "Bearer " + superadminOf(BRAND_X, "root"))
                .exchange().expectStatus().isOk();
    }

    // ════════════════════════════════════════════════════════════════════════════
    // (4) FORGED-TOKEN / UNKNOWN-ISSUER / ANONYMOUS → 401  + verify-never-wrote
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    void foreignUnknownIssuer_evenWithModClaim_is401_andNothingWrote() {
        // A correctly-signed token from an issuer NOT in app.tenancy.issuers: the
        // per-issuer resolver returns Mono.empty() → 401, never accepted, even loaded with
        // mod/admin/superadmin so a fail-open would visibly grant the ban.
        String forged = FOREIGN.mint("attacker", List.of("mod", "admin", "superadmin"));
        post("/bff/mod/ban", forged)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"victim\"}")
                .exchange().expectStatus().isUnauthorized();
        assertNothingWritten();
    }

    @Test
    void tamperedSignature_is401_andNothingWrote() {
        String token = modOf(BRAND_X, "mod-x");
        String tampered = token.substring(0, token.length() - 4) + "AAAA";
        post("/bff/mod/ban", tampered)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"victim\"}")
                .exchange().expectStatus().isUnauthorized();
        assertNothingWritten();
    }

    @Test
    void garbageBearer_is401_andNothingWrote() {
        post("/bff/mod/ban", "not-a-jwt")
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"victim\"}")
                .exchange().expectStatus().isUnauthorized();
        assertNothingWritten();
    }

    @Test
    void anonymous_noToken_is401_andNothingWrote() {
        client.post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"victim\"}")
                .exchange().expectStatus().isUnauthorized();
        assertNothingWritten();
    }

    // ════════════════════════════════════════════════════════════════════════════
    // (5) TEST-SEED GATE — honest disclosure: disabled-by-default ships DARK, no
    //     silent no-op, even for a caller that legitimately clears the role gate.
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    void testSeedFindings_defaultDisabled_is503_forARealMod_andFederationClientNeverReached() {
        // This suite boots the PRODUCTION-shaped profile (no app.test-seed.enabled
        // override anywhere in this class) — exactly the configuration a real
        // deployment would carry. Even a genuine, authenticated MOD principal — who
        // legitimately PASSES the /bff/mod/** role gate — must get a REAL 503, never a
        // silent no-op 200: the honest-disclosure invariant the seed mechanism must
        // uphold.
        post("/bff/mod/findings/test-seed", modOf(BRAND_X, "mod-x"))
                .bodyValue("{}")
                .exchange().expectStatus().isEqualTo(503);
        verify(federation, never()).fileFinding(any(), any());
    }

    @Test
    void testSeedFindings_defaultDisabled_roleUser_is403_beforeTheFlagEvenMatters() {
        // Belt-and-suspenders: a plain user is denied by the SAME chain gate as every
        // other /bff/mod/** route, independent of the test-seed flag.
        post("/bff/mod/findings/test-seed", userOf(BRAND_X, "alice"))
                .bodyValue("{}")
                .exchange().expectStatus().isForbidden();
        verify(federation, never()).fileFinding(any(), any());
    }
}
