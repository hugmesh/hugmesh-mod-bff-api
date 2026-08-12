package net.hugmesh.modbff.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import net.hugmesh.commons.security.DomainRegistry;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * JWT role extraction + domain-scoping helpers — aligned with the hugmesh-gateway
 * {@code net.hugmesh.gateway.security.Roles}. The mod-BFF uses these to derive
 * the brand/domain a moderator is scoped to (from the VALIDATED token issuer, never a
 * user-settable claim) and to read it back off the already-converted Spring
 * authorities ({@code DOMAIN_<x>}).
 *
 * <p>Casdoor's token template can emit the {@code roles} claim in two shapes:
 * <ol>
 *   <li>List of strings:  {@code "roles": ["mod", "admin"]}</li>
 *   <li>List of role objects (default):
 *       {@code "roles": [{"name": "mod", ...}, {"name": "admin", ...}]}</li>
 * </ol>
 * Both shapes are handled. Empty / blank entries are skipped silently so a
 * partially-populated role object doesn't introduce a phantom {@code ROLE_} authority.
 */
public final class Roles {

    private Roles() {}

    /**
     * Non-role marker authority asserting THIS session completed a second factor
     * recently (D8 MFA floor). NOT a Casdoor role and NOT a permission — it is
     * derived ONLY by {@link #isMfaSatisfied(Jwt, long, long)} from the
     * BFF-written, freshness-validated {@code mfa_satisfied_at} JWT-Custom claim,
     * and is added to the converter's RESERVED prefixes so a forged
     * {@code permissions:["MFA_SATISFIED"]} can never inject it. See
     * {@code CasdoorAuthorities}. Copied verbatim from hugmesh-gateway.
     */
    public static final String MFA_SATISFIED = "MFA_SATISFIED";

    /**
     * Flat top-level JWT-Custom claim the admin-bff stamps on a successful
     * BFF-driven MFA challenge: a numeric epoch-MILLIS timestamp carried as a
     * STRING. Casdoor stores {@code User.properties} as a Go {@code map[string]string}
     * (a JSON number is rejected at write time), so the value persists and emits
     * VERBATIM as a string (e.g. {@code "1750233600000"}) — top-level snake_case,
     * NOT camel-cased (Casdoor's SnakeToCamel does not rewrite the
     * {@code Properties.<key>} branch; empirically pinned, workflow wfza2mi09).
     */
    public static final String MFA_SATISFIED_AT_CLAIM = "mfa_satisfied_at";

    /**
     * True iff the JWT carries a FRESH MFA stamp: the BFF-written
     * {@link #MFA_SATISFIED_AT_CLAIM} epoch-millis string parses to a {@code long}
     * {@code ts} satisfying {@code 0 <= now - ts <= freshnessWindowMillis}. A
     * timestamp in the FUTURE ({@code now - ts < 0}) is REJECTED (clock-skew /
     * forged-future defense — a far-future stamp would otherwise never go stale),
     * a STALE one ({@code now - ts > window}) is rejected, and any
     * missing / blank / non-numeric / non-positive value is rejected. Fail-closed
     * throughout — this NEVER throws, it returns {@code false} on every malformed
     * input.
     *
     * <p>The claim is the SOLE source of {@code MFA_SATISFIED}; it is never derived
     * from roles/permissions. {@code now} is passed in (caller supplies
     * {@link System#currentTimeMillis()} in production) so the freshness window is
     * deterministically unit-testable.
     */
    public static boolean isMfaSatisfied(Jwt jwt, long now, long freshnessWindowMillis) {
        if (jwt == null) return false;
        Long ts = mfaSatisfiedAtMillis(jwt);
        if (ts == null) return false;
        long age = now - ts;
        if (age < 0) return false;                    // future timestamp -> reject
        return age <= freshnessWindowMillis;          // within the freshness window
    }

    /**
     * Parse the {@link #MFA_SATISFIED_AT_CLAIM} claim to epoch-millis, or
     * {@code null} when absent / blank / non-numeric / non-positive. Tolerant of
     * the claim arriving as a String (the Casdoor JWT-Custom shape) OR a JSON
     * Number (defensive — should not happen, but parsing it costs nothing). Never
     * throws.
     */
    private static Long mfaSatisfiedAtMillis(Jwt jwt) {
        Object raw = jwt.getClaim(MFA_SATISFIED_AT_CLAIM);
        if (raw == null) return null;
        long ts;
        if (raw instanceof Number n) {
            ts = n.longValue();
        } else {
            String s = raw.toString().trim();
            if (s.isEmpty()) return null;
            try {
                ts = Long.parseLong(s);
            } catch (NumberFormatException e) {
                return null;                          // non-numeric -> fail-closed
            }
        }
        return ts > 0 ? ts : null;                    // non-positive -> fail-closed
    }

    /** Returns every role name carried by the JWT, upper-cased + trimmed. Empty list
     *  if the claim is missing. */
    public static List<String> fromJwt(Jwt jwt) {
        List<String> out = new ArrayList<>();
        if (jwt == null) return out;
        Object claim = jwt.getClaim("roles");
        if (claim instanceof Collection<?> list) {
            for (Object item : list) {
                String name = roleNameOf(item);
                if (!name.isBlank()) out.add(name.toUpperCase(Locale.ROOT));
            }
        }
        return out;
    }

    /** True iff {@code roleName} (case-insensitive) is present in the JWT's roles claim. */
    public static boolean has(Jwt jwt, String roleName) {
        if (jwt == null || roleName == null) return false;
        String want = roleName.trim().toUpperCase(Locale.ROOT);
        for (String r : fromJwt(jwt)) if (r.equals(want)) return true;
        return false;
    }

    /** True iff the principal carries the infra super-role {@code SUPERADMIN}. The ONLY
     *  role exempt from the BFF's per-domain scoping — SUPERADMIN reaches every brand's
     *  data (the infra control plane). Both hyphen and underscore spellings match. */
    public static boolean isSuperadmin(Jwt jwt) {
        return has(jwt, "SUPERADMIN") || has(jwt, "SUPER-ADMIN") || has(jwt, "SUPER_ADMIN");
    }

    /** True iff the principal may build mesh-WORKLOAD images. A separate per-domain
     *  capability (NOT an admin default); both hyphen + underscore spellings match. */
    public static boolean isImageBuilder(Jwt jwt) {
        return has(jwt, "IMAGE-BUILDER") || has(jwt, "IMAGE_BUILDER");
    }

    /** {@code SUPERADMIN} read off an {@link Authentication}'s authorities (the
     *  {@code ROLE_SUPERADMIN} authority the converter emits from the roles claim). The
     *  form the domain-scoping service uses when it holds only the Spring
     *  authorities. */
    public static boolean isSuperadmin(Authentication auth) {
        if (auth == null) return false;
        for (GrantedAuthority a : auth.getAuthorities()) {
            if ("ROLE_SUPERADMIN".equals(a.getAuthority())) return true;
        }
        return false;
    }

    /** The brand/domain this principal is scoped to, derived from the token ISSUER
     *  (per-brand Casdoor =&gt; distinct {@code iss}) through the SAME registry the
     *  converter uses. Returns {@code "default"} for the single-issuer fallback so
     *  single-issuer clusters keep one domain, and (defensively) when
     *  {@code jwt}/{@code registry} is null. A {@code null} from the registry (unknown
     *  issuer in multi-brand mode) is surfaced as-is so the caller can fail closed. */
    public static String domainOf(Jwt jwt, DomainRegistry registry) {
        if (jwt == null || registry == null) return DomainRegistry.DEFAULT_DOMAIN;
        return registry.domainOf(jwt.getIssuer() == null ? null : jwt.getIssuer().toString());
    }

    /** Domain carried on the already-converted authorities ({@code DOMAIN_<x>}) — the
     *  form a caller holding only Spring authorities (no registry) can read.
     *
     *  <p>FAIL-CLOSED on an ambiguous authority set: the canonical converter stamps
     *  EXACTLY ONE issuer-derived {@code DOMAIN_<x>}, so any other count is anomalous —
     *  <ul>
     *    <li>ZERO {@code DOMAIN_} authorities (a hand-built / pre-converter token) — we
     *        can't prove a tenant, so return {@code null}.</li>
     *    <li>MORE THAN ONE {@code DOMAIN_} authority — an INJECTION signature (e.g. a
     *        forged {@code permissions:["DOMAIN_other"]} alongside the genuine issuer
     *        {@code DOMAIN_brandx}); never pick the first, return {@code null}.</li>
     *  </ul>
     *  Returning {@code null} makes a domain-match predicate treat it as a non-match
     *  (deny). Belt-and-suspenders: the converter's reserved-prefix guard already
     *  prevents the injected DOMAIN_ from ever appearing — this overload simply refuses
     *  to be a spoofable side channel. Prefer {@link #domainOf(Jwt, DomainRegistry)}
     *  (issuer-keyed) where a {@link Jwt} is in hand. */
    public static String domainOf(Collection<? extends GrantedAuthority> authorities) {
        if (authorities == null) return null;                       // fail-closed
        String found = null;
        for (GrantedAuthority a : authorities) {
            String s = a.getAuthority();
            if (s != null && s.startsWith("DOMAIN_")) {
                if (found != null) return null;                     // >1 DOMAIN_ -> injection, fail-closed
                found = s.substring("DOMAIN_".length());
            }
        }
        return found;                                               // null when ZERO DOMAIN_ -> fail-closed
    }

    /** Domain read off an {@link Authentication}'s authorities (the principal type the
     *  reactive controllers/service hold). Same fail-closed contract as
     *  {@link #domainOf(Collection)}. */
    public static String domainOf(Authentication auth) {
        return auth == null ? null : domainOf(auth.getAuthorities());
    }

    /**
     * Cross-tenant access predicate — decides whether a resource stamped with
     * {@code rowDomain} is reachable by a caller scoped to {@code callerDomain}. Mirrors
     * the gateway/admin-bff domain-scope rule EXACTLY so every BFF enforces the same
     * boundary:
     * <ul>
     *   <li>{@code SUPERADMIN} (the infra control plane) sees EVERY brand — always
     *       {@code true};</li>
     *   <li>a {@code null}/blank/{@code "default"} {@code rowDomain} is GLOBAL (the
     *       single-tenant / unscoped row, e.g. the canonical seed) and applies to any
     *       caller — {@code true};</li>
     *   <li>otherwise a BRANDED row matches ONLY its own brand: {@code rowDomain} must
     *       equal {@code callerDomain} (case-insensitive, trimmed). A {@code null} caller
     *       domain (the fail-closed signal from {@link #domainOf(Authentication)} on a
     *       zero/&gt;1 {@code DOMAIN_} authority set) NEVER matches a branded row — fail
     *       closed (deny).</li>
     * </ul>
     */
    public static boolean domainApplies(String rowDomain, String callerDomain, boolean isSuperadmin) {
        if (isSuperadmin) return true;                              // infra control plane sees all
        if (rowDomain == null || rowDomain.isBlank()
                || DomainRegistry.DEFAULT_DOMAIN.equalsIgnoreCase(rowDomain.trim())) {
            return true;                                           // global/unscoped row
        }
        if (callerDomain == null || callerDomain.isBlank()) return false; // fail-closed caller
        return rowDomain.trim().equalsIgnoreCase(callerDomain.trim());
    }

    private static String roleNameOf(Object item) {
        if (item == null) return "";
        if (item instanceof String s) return s.trim();
        if (item instanceof Map<?, ?> m) {
            Object name = m.get("name");
            if (name instanceof String s && !s.isBlank()) return s.trim();
        }
        return "";
    }
}
