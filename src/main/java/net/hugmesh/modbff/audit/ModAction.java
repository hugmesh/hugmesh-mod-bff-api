package net.hugmesh.modbff.audit;

import java.time.LocalDateTime;

/**
 * One row of the local R2DBC audit table {@code mod_action} — the BFF's OWN durable
 * record of a moderator action (schema in Liquibase
 * {@code db/changelog/001-mod-action.xml}). Every server-wide block the mod
 * triggers is recorded here regardless of whether the external homeserver admin
 * call succeeded, is degraded, or is STUBBED (the tuwunel/akkoma admin shapes are
 * unconfirmed — see README), so there is always an auditable trail of who did what
 * to whom, and the external result is captured in {@code result}.
 *
 * <ul>
 *   <li>{@code actor}    — the moderator's Casdoor subject (from the JWT).</li>
 *   <li>{@code action}   — e.g. {@code matrix.block-user}, {@code mastodon.block-instance}
 *       (see {@link ModActionType}).</li>
 *   <li>{@code platform} — {@code matrix} | {@code mastodon} | {@code federation}.</li>
 *   <li>{@code target}   — the user MXID / instance domain / acct being acted on.</li>
 *   <li>{@code result}   — {@code stubbed} | {@code ok} | {@code degraded:<reason>}.</li>
 * </ul>
 *
 * <p>The phase-2 ban surface adds four nullable columns (changelog
 * {@code 003-mod-action-ban.xml}); they are {@code null} on the legacy
 * block/refer/recommend rows:
 * <ul>
 *   <li>{@code dedupKey} — a DETERMINISTIC client idempotency key for ban rows, so an
 *       at-least-once redelivery of the same ban is a no-op (a partial unique index
 *       enforces one row per key). {@code null} for non-ban rows.</li>
 *   <li>{@code banType} — {@code user} | {@code instance} | {@code profile}.</li>
 *   <li>{@code expiresAt} — TTL: {@code null} = permanent ban.</li>
 *   <li>{@code propagationState} — {@code pending} | {@code applied} | {@code failed};
 *       a STUBBED/degraded/breaker-open ban stays {@code pending} (never {@code applied}).</li>
 * </ul>
 *
 * <p>App-generated UUID id (portable Postgres + the H2 test DB; no DB-default
 * needed), so the INSERT returns the new row's id.
 *
 * <p>The foundation-auth multi-tenancy work adds the {@code domain} column (changelog
 * {@code 005-mod-action-domain.xml}) — the brand/domain the acting moderator is scoped
 * to, derived from the moderator's CRYPTOGRAPHICALLY-VALIDATED token issuer (the
 * {@code DOMAIN_<x>} authority), NEVER a user-settable claim. The domain-scoped audit
 * reads filter on it so a mod of brand-X only sees brand-X's rows; a SUPERADMIN reads
 * unscoped (every domain). {@code "default"} on single-issuer clusters + legacy rows.
 */
public record ModAction(
        String id,
        String actor,
        String action,
        String platform,
        String target,
        String reason,
        String result,
        LocalDateTime ts,
        String dedupKey,
        String banType,
        LocalDateTime expiresAt,
        String propagationState,
        String domain,
        String notifyChannels,
        Boolean notifyEmailOnly
) {

    /** Construct a legacy (non-ban) row with the four ban columns left null and the
     *  domain defaulted to {@code "default"} (single-tenant). */
    public ModAction(String id, String actor, String action, String platform,
                     String target, String reason, String result, LocalDateTime ts) {
        this(id, actor, action, platform, target, reason, result, ts, null, null, null, null, "default");
    }

    /** Construct a ban-shape row without an explicit domain (defaults to
     *  {@code "default"}) — preserves the pre-multitenancy 12-arg shape used by tests
     *  and the single-tenant path. */
    public ModAction(String id, String actor, String action, String platform,
                     String target, String reason, String result, LocalDateTime ts,
                     String dedupKey, String banType, LocalDateTime expiresAt, String propagationState) {
        this(id, actor, action, platform, target, reason, result, ts,
                dedupKey, banType, expiresAt, propagationState, "default");
    }

    /** Construct a ban-shape row WITH an explicit domain but no notify directive
     *  (Notifications PR6 columns null) — the pre-PR6 13-arg shape used by the
     *  non-notifying path + existing tests. */
    public ModAction(String id, String actor, String action, String platform,
                     String target, String reason, String result, LocalDateTime ts,
                     String dedupKey, String banType, LocalDateTime expiresAt,
                     String propagationState, String domain) {
        this(id, actor, action, platform, target, reason, result, ts,
                dedupKey, banType, expiresAt, propagationState, domain, null, null);
    }
}
