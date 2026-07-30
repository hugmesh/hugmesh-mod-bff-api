package systems.hugmesh.modbff.admin;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import systems.hugmesh.commons.security.DomainRegistry;

import java.util.List;
import java.util.Map;

/**
 * Read-only Casdoor role-membership lookup, used ONLY for the non-privileged target
 * guard on the MOD ban surface: a MOD may NOT ban a user who holds {@code ROLE_ADMIN}
 * or {@code ROLE_MOD}. The acting moderator's own roles come from their JWT; the
 * TARGET is not the caller, so its roles must be resolved out-of-band — here via
 * Casdoor's {@code GET /api/get-role} (the same read the admin-bff
 * {@code CasdoorAdminClient.getRoleMembers} uses), with HTTP Basic
 * ({@code clientId:clientSecret}).
 *
 * <h3>GATED stub-seam (default OFF), audited, never hard-fail</h3>
 * Gated behind {@code casdoor.admin.enabled} (default false) exactly like the
 * homeserver doBlock seam: a Casdoor-less dev/CI run boots clean. With the seam OFF the
 * lookup cannot resolve membership, so the disabled-seam posture is keyed off the
 * caller's tenancy (matching {@code guardSameTenant}'s multi-tenant discriminator): a
 * SINGLE-TENANT caller ({@code null}/blank/{@code "default"} domain) keeps the permissive
 * default (the ban proceeds past the always-on self-ban + method/gateway gates), while a
 * BRANDED caller (a real {@code DOMAIN_<brand>} → multi-tenant / production) FAILS CLOSED
 * — the target is treated as PRIVILEGED so the ban/block/domain-lock is DENIED rather than
 * the privileged-target guard silently no-op'ing when the seam is unwired (finding 6).
 * In-cluster the deployment flips it on with the client credentials so the
 * privileged-target guard is fully enforced for every caller. A transient Casdoor error
 * never hard-fails the request — but with the seam ENABLED it FAILS CLOSED: an erroring
 * role lookup resolves the target as PRIVILEGED so the ban is DENIED (never allowed
 * on an outage), symmetric with {@link #belongsToDomain}. See {@link #isPrivileged}.
 * The endpoint stays a 403-on-privileged guard whenever Casdoor is reachable.
 */
public class CasdoorRoleClient {

    private static final Logger log = LoggerFactory.getLogger(CasdoorRoleClient.class);

    /** Parameterized type reference for a {@code Map<String,Object>} JSON body, avoiding
     *  the raw-{@code Map.class} unchecked-cast that {@code bodyToMono} would otherwise
     *  require. */
    private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP =
            new ParameterizedTypeReference<>() {};

    /** The roles a MOD ban target may NOT hold (admins + fellow mods are protected). */
    static final List<String> PRIVILEGED_ROLES = List.of("ROLE_ADMIN", "ROLE_MOD");

    private final WebClient http;
    private final String organization;
    private final boolean enabled;
    /** caller-domain ({@code DOMAIN_<x>}) -&gt; the per-brand Casdoor org that brand's
     *  users live in. Lets the privileged-target + same-tenant lookups key off the
     *  CALLER's brand org rather than the single static {@link #organization}. */
    private final Map<String, String> domainOrgMap;

    public CasdoorRoleClient(final WebClient webClient, String organization, boolean enabled) {
        this(webClient, organization, enabled, Map.of());
    }

    public CasdoorRoleClient(final WebClient webClient, String organization, boolean enabled,
                             Map<String, String> domainOrgMap) {
        this.http = webClient;
        this.organization = organization;
        this.enabled = enabled;
        this.domainOrgMap = domainOrgMap == null ? Map.of() : domainOrgMap;
    }

    /** Whether Casdoor membership resolution is wired (flag on + creds present). */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * The Casdoor org for a caller's {@code DOMAIN_<x>} brand. Resolved from the
     * configured {@code domainOrgMap}; falls back to the single static
     * {@link #organization} when no per-brand mapping is configured (single-tenant /
     * legacy) OR when the caller's domain is null/blank/{@code "default"} (the
     * single-tenant domain). NEVER returns a different brand's org for an unknown
     * domain — an unmapped branded domain falls back to the static org, which on a
     * multi-brand cluster will simply not contain the cross-brand target (so the
     * same-tenant guard fails closed).
     */
    String orgForDomain(String callerDomain) {
        if (isSingleTenant(callerDomain)) {
            return organization;
        }
        return domainOrgMap.getOrDefault(callerDomain.trim(), organization);
    }

    /**
     * True when {@code callerDomain} is the single-tenant inert domain — null, blank, or
     * {@code "default"} — i.e. the cluster is NOT in multi-brand mode (one Casdoor org,
     * one domain). Mirrors the {@link systems.hugmesh.modbff.service.ModService}
     * {@code guardSameTenant} single-tenant leg and {@link DomainRegistry#DEFAULT_DOMAIN},
     * so the privileged-target + tenant guards share ONE multi-tenant discriminator.
     */
    private static boolean isSingleTenant(String callerDomain) {
        return callerDomain == null || callerDomain.isBlank()
                || DomainRegistry.DEFAULT_DOMAIN.equalsIgnoreCase(callerDomain.trim());
    }

    /**
     * True if {@code target} holds {@code ROLE_ADMIN} or {@code ROLE_MOD} — i.e. is a
     * PRIVILEGED user a MOD may not ban. The single-arg form passes a {@code null}
     * (single-tenant) caller domain, so a disabled seam keeps the permissive default;
     * the domain-aware {@link #isPrivileged(String, String)} fails CLOSED for a branded
     * (multi-tenant) caller. With the seam ENABLED a reachable-but-erroring Casdoor
     * FAILS CLOSED — it resolves to {@code true} after logging (the target is
     * conservatively treated as privileged so the ban is denied), never a hard-fail of
     * the request, never an OPEN allow.
     *
     * <p>{@code target} is matched against the {@code users} list of each privileged
     * role, which Casdoor returns as {@code <org>/<name>} ids — so a bare username and
     * the org-qualified form are both checked.
     */
    public Mono<Boolean> isPrivileged(String target) {
        return isPrivileged(target, null);
    }

    /**
     * Domain-aware {@link #isPrivileged(String)}: resolves the privileged-role
     * membership in the CALLER's per-brand Casdoor org (via {@link #orgForDomain}) so a
     * brand-X MOD's privileged-target check reads brand-X's {@code ROLE_ADMIN}/
     * {@code ROLE_MOD} membership, not another brand's.
     *
     * <p><strong>DISABLED-seam posture (the finding-6 fail-closed fix).</strong> When the
     * seam is OFF (no Casdoor creds), the target's roles are UNPROVABLE. The choice then
     * mirrors {@code guardSameTenant}'s multi-tenant discriminator EXACTLY:
     * <ul>
     *   <li>a SINGLE-TENANT caller ({@code null}/blank/{@code "default"} domain — the
     *       legacy single Casdoor org / dev / CI flow) keeps the permissive default
     *       ({@code false} → not privileged): there is one org, the always-on self-ban +
     *       method/gateway gates still apply, and ordinary moderation keeps working
     *       offline exactly as before;</li>
     *   <li>a BRANDED caller (a real {@code DOMAIN_<brand>} → multi-tenant / production
     *       posture) FAILS CLOSED — resolves {@code true} (target treated as PRIVILEGED,
     *       the ban/block/domain-lock is DENIED), matching {@link #belongsToDomain}'s
     *       fail-closed contract for an unprovable target. Previously this branch failed
     *       OPEN ({@code false}) so a MOD could ban an ADMIN/MOD whenever the seam was
     *       left unwired (the default) — finding 6.</li>
     * </ul>
     */
    public Mono<Boolean> isPrivileged(String target, String callerDomain) {
        if (!enabled) {
            // Multi-tenant/production caller (branded) → fail CLOSED: an unprovable target
            // is treated as PRIVILEGED so the privileged-target mutation is denied. A
            // single-tenant (null/blank/'default') caller keeps the permissive default so
            // the offline dev/CI + single-org flow still bans ordinary users.
            boolean failClosed = !isSingleTenant(callerDomain);
            log.debug("[casdoor] role-guard DISABLED — privileged-target check for {} (domain {}) "
                    + "resolves {} (branded caller fails closed)", target, callerDomain, failClosed);
            return Mono.just(failClosed);
        }
        String org = orgForDomain(callerDomain);
        return Mono.zip(
                        membersOf(org, "ROLE_ADMIN"),
                        membersOf(org, "ROLE_MOD"))
                .map(t -> contains(org, t.getT1(), target) || contains(org, t.getT2(), target))
                // FAIL CLOSED on a Casdoor outage (enabled seam): an erroring role lookup
                // must NOT let a MOD ban an ADMIN/MOD. Previously membersOf swallowed the
                // error to an empty list → privileged=false → the ban was ALLOWED (failed
                // OPEN), asymmetric with belongsToDomain (which fails closed). Now an error
                // resolves privileged=TRUE so the ban is DENIED — conservatively treating an
                // unresolvable target as protected. (The disabled-seam dev/CI path above
                // still short-circuits to false and never reaches Casdoor.)
                .onErrorResume(e -> {
                    log.warn("[casdoor] privileged-role lookup for {} (org {}) failed — "
                            + "fail closed (treated as PRIVILEGED, ban denied): {}", target, org, e.toString());
                    return Mono.just(true);
                });
    }

    /**
     * AUTHORITATIVE same-tenant check for the cross-domain moderation guard: true iff
     * {@code target} is a member of the CALLER's per-brand Casdoor org (resolved off
     * {@code callerDomain} via {@link #orgForDomain}). Asks Casdoor
     * {@code GET /api/get-user?id=<org>/<target>} — the org-qualified id makes the read
     * brand-scoped, so a target who lives in a DIFFERENT brand's org resolves ABSENT
     * (the {@code data} is null) and the guard denies the cross-tenant write.
     *
     * <p>When the seam is DISABLED (no Casdoor creds — dev/CI), the target's tenant
     * cannot be proven, so this returns {@code false} (membership UNKNOWN → fail closed):
     * a Casdoor-less run cannot drive a cross-domain ban. A reachable-but-erroring
     * Casdoor likewise resolves to {@code false} after logging — never a hard-fail, but
     * never an OPEN either. (Contrast {@link #isPrivileged}, whose unknown-membership
     * default is permissive because it is an ADDITIONAL restriction; the tenant check is
     * a PRECONDITION and so must fail closed.)
     */
    public Mono<Boolean> belongsToDomain(String target, String callerDomain) {
        if (target == null || target.isBlank()) return Mono.just(false);
        if (!enabled) {
            log.debug("[casdoor] tenant-guard membership UNKNOWN (seam disabled) for {} — fail closed", target);
            return Mono.just(false);
        }
        String org = orgForDomain(callerDomain);
        return http.get()
                .uri(uri -> uri.path("/api/get-user")
                        .queryParam("id", org + "/" + target).build())
                .retrieve()
                .bodyToMono(STRING_OBJECT_MAP)
                .map(body -> body.get("data") instanceof Map<?, ?>)
                .defaultIfEmpty(false)
                .onErrorResume(e -> {
                    log.warn("[casdoor] get-user {}/{} failed (tenant unknown → fail closed): {}",
                            org, target, e.toString());
                    return Mono.just(false);
                });
    }

    private boolean contains(String org, List<String> members, String target) {
        if (target == null) return false;
        String qualified = org + "/" + target;
        return members.contains(target) || members.contains(qualified);
    }

    private Mono<List<String>> membersOf(String org, String roleName) {
        return http.get()
                .uri(uri -> uri.path("/api/get-role")
                        .queryParam("id", org + "/" + roleName).build())
                .retrieve()
                .bodyToMono(STRING_OBJECT_MAP)
                .map(body -> {
                    Object data = body.get("data");
                    if (data instanceof Map<?, ?> m && m.get("users") instanceof List<?> list) {
                        return list.stream().map(String::valueOf).toList();
                    }
                    return List.<String>of();
                });
        // NOTE: errors are DELIBERATELY NOT swallowed here. A get-role failure propagates
        // to isPrivileged(...), which fails CLOSED (resolves privileged=true → ban denied).
        // Swallowing to an empty list here would fail OPEN (the bug this fixes).
    }
}
