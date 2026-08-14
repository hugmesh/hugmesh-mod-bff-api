package net.hugmesh.modbff.security;

import net.hugmesh.commons.security.DomainRegistry;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link Roles} — JWT role extraction + domain-scoping helpers (copied from the
 * gateway). Delineated per the test standard.
 *
 * <ul>
 *   <li>USER-SITUATIONAL — a single token's roles + super-role + issuer domain.</li>
 *   <li>MULTIUSER-SITUATIONAL — per-issuer domain resolution across brands.</li>
 *   <li>CROSS-USER — domainOf(authorities) FAILS CLOSED on a forged/ambiguous DOMAIN_
 *       set; isSuperadmin is NOT satisfiable by an injected permission.</li>
 * </ul>
 */
class RolesTest {

    private static Jwt jwtWith(Map<String, Object> claims) {
        return Jwt.withTokenValue("test").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                .subject("user-id-123").claims(c -> c.putAll(claims)).build();
    }

    private static Jwt jwtWithIssuer(String issuer, Map<String, Object> claims) {
        return Jwt.withTokenValue("test").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60))
                .subject("user-id-123").issuer(issuer).claims(c -> c.putAll(claims)).build();
    }

    private static Authentication auth(GrantedAuthority... authorities) {
        return new UsernamePasswordAuthenticationToken("p", "n/a", List.of(authorities));
    }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────
    @Nested
    class UserSituational {

        @Test
        void fromJwt_handlesStringAndObjectRoleShapes() {
            assertThat(Roles.fromJwt(jwtWith(Map.of("roles", List.of("mod", "admin")))))
                    .containsExactlyInAnyOrder("MOD", "ADMIN");
            assertThat(Roles.fromJwt(jwtWith(Map.of("roles", List.of(Map.of("name", "mod"))))))
                    .containsExactly("MOD");
        }

        @Test
        void isSuperadmin_matchesEitherSpelling_andOnlySuperadmin() {
            assertThat(Roles.isSuperadmin(jwtWith(Map.of("roles", List.of("superadmin"))))).isTrue();
            assertThat(Roles.isSuperadmin(jwtWith(Map.of("roles", List.of("super-admin"))))).isTrue();
            assertThat(Roles.isSuperadmin(jwtWith(Map.of("roles", List.of("super_admin"))))).isTrue();
            // a plain admin is NOT a superadmin (the cross-domain bypass must not leak)
            assertThat(Roles.isSuperadmin(jwtWith(Map.of("roles", List.of("admin"))))).isFalse();
            assertThat(Roles.isSuperadmin(jwtWith(Map.of("isAdmin", true)))).isFalse();
        }

        @Test
        void isImageBuilder_matchesEitherSpelling_notAdminDefault() {
            assertThat(Roles.isImageBuilder(jwtWith(Map.of("roles", List.of("image_builder"))))).isTrue();
            assertThat(Roles.isImageBuilder(jwtWith(Map.of("roles", List.of("image-builder"))))).isTrue();
            assertThat(Roles.isImageBuilder(jwtWith(Map.of("roles", List.of("admin"))))).isFalse();
        }

        @Test
        void isSuperadmin_authorities_readsRoleSuperadmin() {
            assertThat(Roles.isSuperadmin(auth(
                    new SimpleGrantedAuthority("ROLE_USER"),
                    new SimpleGrantedAuthority("ROLE_SUPERADMIN")))).isTrue();
            assertThat(Roles.isSuperadmin(auth(
                    new SimpleGrantedAuthority("ROLE_USER"),
                    new SimpleGrantedAuthority("ROLE_MOD")))).isFalse();
            assertThat(Roles.isSuperadmin((Authentication) null)).isFalse();
        }

        @Test
        void domainOf_jwt_viaRegistry_singleIssuerIsDefault() {
            DomainRegistry reg = new DomainRegistry("https://id.hugmesh.net", "");
            Jwt jwt = jwtWithIssuer("https://id.hugmesh.net", Map.of("roles", List.of("mod")));
            assertThat(Roles.domainOf(jwt, reg)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            // defensive null inputs
            assertThat(Roles.domainOf((Jwt) null, reg)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
            assertThat(Roles.domainOf(jwt, null)).isEqualTo(DomainRegistry.DEFAULT_DOMAIN);
        }
    }

    // ── MULTIUSER-SITUATIONAL ─────────────────────────────────────────────────
    @Nested
    class MultiUserSituational {

        @Test
        void domainOf_jwt_viaRegistry_multiBrand_perIssuer_andFailClosed() {
            DomainRegistry reg = new DomainRegistry("https://id.brandx.tld",
                    "https://id.brandx.tld=brandx,https://id.brandy.tld=brandy");
            assertThat(Roles.domainOf(jwtWithIssuer("https://id.brandx.tld", Map.of()), reg))
                    .isEqualTo("brandx");
            assertThat(Roles.domainOf(jwtWithIssuer("https://id.brandy.tld", Map.of()), reg))
                    .isEqualTo("brandy");
            // untrusted issuer -> null (caller fails closed)
            assertThat(Roles.domainOf(jwtWithIssuer("https://evil.tld", Map.of()), reg)).isNull();
        }

        @Test
        void domainOf_authorities_exactlyOneDomain_isReturned() {
            assertThat(Roles.domainOf(List.of(
                    new SimpleGrantedAuthority("ROLE_USER"),
                    new SimpleGrantedAuthority("ROLE_MOD"),
                    new SimpleGrantedAuthority("DOMAIN_brandx")))).isEqualTo("brandx");
            // the Authentication overload reads the same
            assertThat(Roles.domainOf(auth(
                    new SimpleGrantedAuthority("ROLE_MOD"),
                    new SimpleGrantedAuthority("DOMAIN_brandy")))).isEqualTo("brandy");
        }
    }

    // ── CROSS-USER — fail-closed / injection defense ──────────────────────────
    @Nested
    class CrossUser_FailClosed {

        @Test
        void isSuperadmin_false_whenSuperadminIsOnlyAnInjectedPermission() {
            // AUTHORITY-INJECTION REGRESSION: superadmin is derived from the ROLES
            // claim, never from `permissions`. A token whose only "superadmin" signal is
            // a forged permissions entry is NOT treated as superadmin.
            Jwt injected = jwtWith(Map.of(
                    "roles", List.of("user"),
                    "permissions", List.of("ROLE_SUPERADMIN", "SUPERADMIN")));
            assertThat(Roles.isSuperadmin(injected)).isFalse();
        }

        // ── domainApplies: the cross-tenant access predicate (the A01 fix) ──────
        @Test
        void domainApplies_superadmin_seesEveryBrand() {
            // SUPERADMIN bypasses scoping entirely — even a foreign branded row applies.
            assertThat(Roles.domainApplies("brandy", "brandx", true)).isTrue();
            assertThat(Roles.domainApplies("brandx", null, true)).isTrue();
        }

        @Test
        void domainApplies_globalRow_appliesToAnyCaller() {
            // null/blank/'default' row domain = unscoped/global (single-tenant + seed).
            assertThat(Roles.domainApplies(null, "brandx", false)).isTrue();
            assertThat(Roles.domainApplies("", "brandx", false)).isTrue();
            assertThat(Roles.domainApplies(" ", "brandx", false)).isTrue();
            assertThat(Roles.domainApplies("default", "brandx", false)).isTrue();
            assertThat(Roles.domainApplies("DEFAULT", "brandx", false)).isTrue();
        }

        @Test
        void domainApplies_brandedRow_matchesOnlyItsOwnBrand() {
            // SAME brand → allow; CROSS brand → deny (the cross-tenant BFLA boundary).
            assertThat(Roles.domainApplies("brandx", "brandx", false)).isTrue();
            assertThat(Roles.domainApplies("BrandX", " brandx ", false)).isTrue(); // case/trim tolerant
            assertThat(Roles.domainApplies("brandy", "brandx", false)).isFalse();
        }

        @Test
        void domainApplies_brandedRow_failsClosed_onNullCaller() {
            // A null caller domain (the zero/>1 DOMAIN_ fail-closed signal) NEVER matches
            // a branded row — deny.
            assertThat(Roles.domainApplies("brandx", null, false)).isFalse();
            assertThat(Roles.domainApplies("brandx", "", false)).isFalse();
        }

        @Test
        void domainOf_authorities_failsClosed_onZeroOrMultipleDomain() {
            // ZERO DOMAIN_ (hand-built / pre-converter token) -> null (deny).
            assertThat(Roles.domainOf(List.of(
                    new SimpleGrantedAuthority("ROLE_USER"),
                    new SimpleGrantedAuthority("ROLE_MOD")))).isNull();
            // MORE THAN ONE DOMAIN_ (INJECTION: forged DOMAIN_brandy alongside genuine
            // DOMAIN_brandx) -> null (deny); never the first one wins.
            assertThat(Roles.domainOf(List.of(
                    new SimpleGrantedAuthority("ROLE_USER"),
                    new SimpleGrantedAuthority("DOMAIN_brandy"),   // injected first
                    new SimpleGrantedAuthority("DOMAIN_brandx")))) // genuine issuer
                    .isNull();
            // null inputs -> null (deny).
            assertThat(Roles.domainOf((java.util.Collection<GrantedAuthority>) null)).isNull();
            assertThat(Roles.domainOf((Authentication) null)).isNull();
        }
    }

    /**
     * D8 MFA freshness — {@code Roles.isMfaSatisfied(jwt, now, window)} (fan-out parity
     * with the gateway). Reads the top-level snake_case {@code mfa_satisfied_at} claim,
     * tolerant of String AND Number, fail-closed on every malformed input, FUTURE
     * rejected; never throws.
     */
    @Nested
    class MfaFreshness {

        private static final long WINDOW = 600_000L;   // 10 min
        private static final long NOW = 1_750_000_000_000L;

        private static Jwt mfaJwt(Object satisfiedAt) {
            return jwtWith(Map.of("mfa_satisfied_at", satisfiedAt));
        }

        @Test
        void freshStampString_withinWindow_true() {
            long now = NOW;
            // Well inside the window.
            assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now - 60_000L)), now, WINDOW)).isTrue();
            // Exactly at the window edge (age == window).
            assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now - WINDOW)), now, WINDOW)).isTrue();
            // Right now (age == 0).
            assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now)), now, WINDOW)).isTrue();
        }

        @Test
        void staleStamp_pastWindow_false() {
            long now = NOW;
            assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now - WINDOW - 1)), now, WINDOW)).isFalse();
            assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now - 3_600_000L)), now, WINDOW)).isFalse();
        }

        @Test
        void futureStamp_rejected() {
            long now = NOW;
            assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now + 1)), now, WINDOW)).isFalse();
            assertThat(Roles.isMfaSatisfied(mfaJwt(Long.toString(now + 3_600_000L)), now, WINDOW)).isFalse();
        }

        @Test
        void missingOrMalformed_failsClosed() {
            long now = NOW;
            assertThat(Roles.isMfaSatisfied(jwtWith(Map.of("roles", List.of("admin"))), now, WINDOW)).isFalse();
            assertThat(Roles.isMfaSatisfied(mfaJwt("   "), now, WINDOW)).isFalse();
            assertThat(Roles.isMfaSatisfied(mfaJwt("not-a-number"), now, WINDOW)).isFalse();
            assertThat(Roles.isMfaSatisfied(mfaJwt("0"), now, WINDOW)).isFalse();
            assertThat(Roles.isMfaSatisfied(mfaJwt("-1"), now, WINDOW)).isFalse();
            assertThat(Roles.isMfaSatisfied(null, now, WINDOW)).isFalse();
        }

        @Test
        void numericClaim_alsoTolerated() {
            long now = NOW;
            assertThat(Roles.isMfaSatisfied(mfaJwt(now - 60_000L), now, WINDOW)).isTrue();
            assertThat(Roles.isMfaSatisfied(mfaJwt(now + 1L), now, WINDOW)).isFalse();   // future number rejected
        }
    }
}
