package systems.hugmesh.modbff.audit;

/**
 * The moderator-action verbs recorded in {@code mod_action}. Kept as a small set
 * of constants (not a free-form string at the call site) so the audit log stays
 * queryable and the README/UI can enumerate them. A MOD's surface is intentionally
 * narrow: block at the homeserver level + escalate; there is NO direct user
 * removal (that escalates to admin via federation-api refer).
 */
public final class ModActionType {

    private ModActionType() {}

    public static final String MATRIX_BLOCK_USER       = "matrix.block-user";
    public static final String MATRIX_BLOCK_INSTANCE   = "matrix.block-instance";
    public static final String MASTODON_BLOCK_USER     = "mastodon.block-user";
    public static final String MASTODON_BLOCK_INSTANCE = "mastodon.block-instance";
    /** A mod refers a user-removal/instance-block recommendation up to an admin. */
    public static final String FEDERATION_REFER        = "federation.refer";
    /** A mod records a recommendation into the federation moderation queue. */
    public static final String FEDERATION_RECOMMEND    = "federation.recommend";
    /**
     * A mod RESOLVES a system finding (automated edge-AI avatar/image moderation):
     * {@code actioned=true} → the mod took action, {@code false} → the mod dismissed it.
     * The federation row also records the reviewer; this verb makes the resolve
     * first-class in the local domain-scoped moderation audit trail. The platform
     * value is {@code federation}.
     */
    public static final String FEDERATION_FINDING_RESOLVE = "federation.finding-resolve";

    /**
     * A mod BANs a user from a platform-access role: writes the {@code access_suspension}
     * desired-state in admin-bff (the single-writer reconcile loop applies it) and
     * records the intent locally. The platform value is {@code access}.
     */
    public static final String ACCESS_SUSPEND          = "access.suspend";
    /** A mod LIFTS a previously written ban (clears the access_suspension desired-state). */
    public static final String ACCESS_RESTORE          = "access.restore";

    /**
     * A mod DOMAIN-LOCKS a user (forces local-only / no-federation): writes the
     * {@code domain_lock} desired-state in admin-bff (the single-writer reconcile loop
     * applies the {@code ROLE_*_DOMAINLOCKED} marker + the homeserver/egress force-local
     * enforcement). ADD-semantics — the user KEEPS {@code ROLE_MATRIX}/{@code ROLE_MASTODON}.
     * The platform value is {@code domain-lock}.
     */
    public static final String DOMAIN_LOCK             = "domain.lock";
    /** A mod UNLOCKS a previously domain-locked user (clears the domain_lock desired-state). */
    public static final String DOMAIN_UNLOCK           = "domain.unlock";

    /*
     * WIKI access-overlay moderation events. The grant/timeout/ban/restore overlay is
     * owned by the SEPARATE hugmesh-wiki-bff-api (the {@code wiki_access} desired-state
     * table, cloned in shape from admin-bff {@code access_suspension}); these verbs make
     * those events FIRST-CLASS in this BFF's moderation audit/queue surface so a wiki
     * grant/timeout/ban/restore is recorded alongside the matrix/mastodon/access/domain-lock
     * actions. Domain-scoped like the rest. The platform value is {@code wiki} (sibling of
     * {@code access} / {@code domain-lock} — a NON-homeserver platform whose effect lives in
     * a desired-state table, not a tuwunel/akkoma call).
     */
    /** A mod GRANTS a user wiki read access (writes an active wiki_access read override). */
    public static final String WIKI_GRANT              = "wiki.grant";
    /** A mod TIMES a user OUT of the wiki (a wiki_access banned override with a future
     *  expiry that auto-restores on expiry). */
    public static final String WIKI_TIMEOUT            = "wiki.timeout";
    /** A mod BANS a user from the wiki (a permanent wiki_access banned override). */
    public static final String WIKI_BAN                = "wiki.ban";
    /** A mod RESTORES wiki access (revokes the active grant/ban/timeout override). */
    public static final String WIKI_RESTORE            = "wiki.restore";

    /**
     * OWNCAST live-stream moderation events. The kill/hide/restore EFFECT is owned by
     * the SEPARATE hugmesh-owncast-bff-api ({@code /bff/owncast/mod/streams/...} —
     * ban/restore reuse its {@code owncast_grant} desired-state; hide flips
     * {@code owncast_stream.visibility}); these verbs make those events FIRST-CLASS in
     * this BFF's central moderation ledger, recorded when a moderator drives the action
     * through {@code /bff/mod/owncast/**} (the {@code OwncastModClient} effector call +
     * the ledger row, mirroring how the admin-bff ban/domain-lock writes are recorded).
     * Domain-scoped like the rest. The platform value is {@code owncast} (a
     * NON-homeserver platform, sibling of {@code access} / {@code domain-lock} /
     * {@code wiki}). owncast-bff's local {@code owncast_moderation_audit} journal is
     * ALSO written by the effector — the two records are complementary, not redundant:
     * this one is the cross-platform brand ledger, that one the service-local journal.
     */
    /** A mod HIDES a target owner's stream (forces visibility=internal; no grant change). */
    public static final String OWNCAST_HIDE            = "owncast.hide";
    /** A mod KILLS a stream: owncast_grant(banned) active + hide (the owncast-bff kill). */
    public static final String OWNCAST_KILL            = "owncast.kill";
    /** A mod RESTORES a killed owner (active ban CASed to revoked; no auto-republish). */
    public static final String OWNCAST_RESTORE         = "owncast.restore";
}
