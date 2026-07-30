package systems.hugmesh.modbff.audit;

import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;

/**
 * Reactive (R2DBC) store for the BFF's OWN {@code mod_action} audit table (schema
 * in Liquibase {@code db/changelog/001-mod-action.xml}). IDs are DB-GENERATED — the
 * {@code id} column carries a {@code gen_random_uuid()} DEFAULT (pgcrypto, changelog
 * 009), so the INSERT omits {@code id} and reads the generated UUID back via
 * {@code RETURNING id} (the app no longer mints {@code UUID.randomUUID()}). This is the
 * ONLY runtime datastore this BFF owns — all moderation/manifest
 * state lives in federation-api; the homeserver state lives in tuwunel/akkoma. The
 * audit table is the local source of truth for "what did a moderator do".
 *
 * <p>Data-access standard (2026-06-18): this class is now a thin FACADE over the
 * Spring Data {@link ModActionR2dbcRepository} interface — no raw {@code DatabaseClient}
 * query strings. Reads are DERIVED query methods; the two
 * DB-generated-id INSERTs (each omits {@code id}, lets the {@code gen_random_uuid()}
 * column DEFAULT fill it, and reads it back via {@code RETURNING id} — including the ban
 * path's {@code ON CONFLICT DO NOTHING} idempotency, whose RETURNING-yields-no-row on a
 * conflict IS the deduped signal) are {@code @Query} with static-final SQL constants. The
 * facade preserves the {@link ModAction} API/DTO conversion.
 *
 * <p>BOUNDED audit reads (DoS hardening): the four {@code GET /bff/mod/audit} finder
 * variants ({@link #list(int)}, {@link #listByActor(String, int)},
 * {@link #listForDomain(String, int)}, {@link #listByActorForDomain(String, String, int)})
 * each take a {@code limit} that is clamped server-side to {@code [1, MAX_AUDIT_LIMIT]}
 * ({@link #clampLimit(int)}) and pushed into a SQL {@code ORDER BY ts DESC LIMIT :limit},
 * so an audit read returns at most the {@code MAX_AUDIT_LIMIT} NEWEST rows and can never
 * stream the whole {@code mod_action} table into memory. The actor/domain scoping
 * predicates (and the {@code null}-domain fail-closed contract) are unchanged.
 */
@Repository
public class ModActionRepository {

    private final ModActionR2dbcRepository repo;

    public ModActionRepository(ModActionR2dbcRepository repo) {
        this.repo = repo;
    }

    /** Single-tenant / legacy domain fallback (mirrors
     *  {@code DomainRegistry.DEFAULT_DOMAIN}); stamped when the caller does not supply a
     *  domain (single-issuer path) so a row is NEVER un-scoped. */
    private static final String DEFAULT_DOMAIN = "default";

    /** Default audit-trail page size when the caller supplies no {@code ?limit=}. The
     *  {@code GET /bff/mod/audit} read is bounded so a moderator's view can never stream
     *  the whole {@code mod_action} table into memory (the unbounded-table DoS). */
    public static final int DEFAULT_AUDIT_LIMIT = 200;

    /** Hard server-side cap: a caller-supplied {@code ?limit=} is clamped to this ceiling
     *  (and a floor of 1), so even an attacker-chosen value cannot un-bound the read. */
    public static final int MAX_AUDIT_LIMIT = 1000;

    /**
     * Clamp a caller-influenced limit to {@code [1, MAX_AUDIT_LIMIT]}. Defense-in-depth:
     * the controller already clamps {@code ?limit=}, but the facade clamps AGAIN so every
     * caller (controller, service, future internal caller) is bounded — a non-positive or
     * over-cap value can never reach the SQL {@code LIMIT}.
     */
    public static int clampLimit(int limit) {
        if (limit < 1) return DEFAULT_AUDIT_LIMIT;                   // non-positive -> default
        return Math.min(limit, MAX_AUDIT_LIMIT);                     // ceiling at the hard cap
    }

    /** All audit rows, newest first, BOUNDED to {@code limit} (clamped to the hard cap).
     *  UNSCOPED — the SUPERADMIN (cross-domain infra control plane) view ONLY. A
     *  per-domain moderator/admin MUST use {@link #listForDomain(String, int)} so they
     *  never see another brand's rows. */
    public Flux<ModAction> list(int limit) {
        return repo.findNewest(clampLimit(limit)).map(ModActionRow::toModAction);
    }

    /** Back-compat / convenience: {@link #list(int)} at the {@link #DEFAULT_AUDIT_LIMIT}.
     *  STILL BOUNDED — there is no un-capped variant. */
    public Flux<ModAction> list() {
        return list(DEFAULT_AUDIT_LIMIT);
    }

    /** Audit rows for one actor (moderator), newest first, BOUNDED. UNSCOPED across
     *  domains — the SUPERADMIN view of one actor. Per-domain callers use
     *  {@link #listByActorForDomain(String, String, int)}. */
    public Flux<ModAction> listByActor(String actor, int limit) {
        return repo.findByActorNewest(actor, clampLimit(limit)).map(ModActionRow::toModAction);
    }

    /** Back-compat / convenience: {@link #listByActor(String, int)} at the default cap. */
    public Flux<ModAction> listByActor(String actor) {
        return listByActor(actor, DEFAULT_AUDIT_LIMIT);
    }

    /** DOMAIN-SCOPED audit read: rows for one brand/domain, newest first, BOUNDED. The
     *  cross-domain isolation boundary — a brand-X moderator/admin reads ONLY brand-X's
     *  rows. A {@code null} domain (fail-closed signal from
     *  {@code Roles.domainOf(authorities)} — zero or &gt;1 DOMAIN_ authority) yields an
     *  EMPTY flux: an ambiguous/unprovable tenant sees nothing, never another brand's
     *  data. */
    public Flux<ModAction> listForDomain(String domain, int limit) {
        if (domain == null) return Flux.empty();                    // fail-closed: deny
        return repo.findByDomainNewest(domain, clampLimit(limit)).map(ModActionRow::toModAction);
    }

    /** Back-compat / convenience: {@link #listForDomain(String, int)} at the default cap.
     *  Same fail-closed {@code null}-domain contract. */
    public Flux<ModAction> listForDomain(String domain) {
        return listForDomain(domain, DEFAULT_AUDIT_LIMIT);
    }

    /** DOMAIN-SCOPED audit read for one actor: rows for {@code actor} WITHIN
     *  {@code domain} only, newest first, BOUNDED. Same fail-closed {@code null}-domain
     *  contract as {@link #listForDomain(String, int)}. */
    public Flux<ModAction> listByActorForDomain(String actor, String domain, int limit) {
        if (domain == null) return Flux.empty();                    // fail-closed: deny
        return repo.findByActorAndDomainNewest(actor, domain, clampLimit(limit))
                .map(ModActionRow::toModAction);
    }

    /** Back-compat / convenience: {@link #listByActorForDomain(String, String, int)} at
     *  the default cap. Same fail-closed {@code null}-domain contract. */
    public Flux<ModAction> listByActorForDomain(String actor, String domain) {
        return listByActorForDomain(actor, domain, DEFAULT_AUDIT_LIMIT);
    }

    /**
     * Record a moderator action (DB-generated id + app-stamped ts) in the single-tenant /
     * {@code "default"} domain. Back-compat shape; the domain-aware
     * {@link #record(String, String, String, String, String, String, String)} stamps a
     * caller-supplied brand.
     */
    public Mono<ModAction> record(String actor, String action, String platform,
                                  String target, String reason, String result) {
        return record(actor, action, platform, target, reason, result, DEFAULT_DOMAIN);
    }

    /**
     * Record a moderator action (DB-generated id + app-stamped ts) STAMPED WITH {@code domain} and
     * return it with the id + ts populated. The {@code result} captures the external
     * call outcome (e.g. {@code stubbed}) so the trail is honest about deferred
     * integrations. The {@code domain} is the acting moderator's brand — derived from
     * the VALIDATED token issuer ({@code DOMAIN_<x>} authority), never a user claim — so
     * the domain-scoped reads can isolate it to that brand. A {@code null}/blank domain
     * defensively falls back to {@code "default"} so a row is never un-scoped.
     */
    public Mono<ModAction> record(String actor, String action, String platform,
                                  String target, String reason, String result, String domain) {
        LocalDateTime ts = LocalDateTime.now();
        String dom = domainOrDefault(domain);
        // The id is DB-generated (gen_random_uuid() DEFAULT, changelog 009); the INSERT
        // omits it and RETURNING id hands back the generated UUID, which we render into
        // the returned ModAction (same field order/values as before).
        return repo.insertActionReturningId(actor, action, platform, target, reason, result, ts, dom)
                .map(genId -> new ModAction(genId.toString(), actor, action, platform, target,
                        reason, result, ts, null, null, null, null, dom));
    }

    /**
     * Record a BAN/lift action IDEMPOTENTLY against a deterministic client dedup key.
     * The ban write path (admin-bff access-suspension submit) is at-least-once, so a
     * redelivered ban must NOT create a second row or re-trigger the effect. The INSERT
     * is {@code ON CONFLICT DO NOTHING ... RETURNING id} (the COMPOSITE unique index on
     * {@code (dedup_key, domain)} enforces one row per key PER BRAND); a fresh insert
     * RETURNs the DB-generated id ({@code fresh=true}), a deduped retry RETURNs no row
     * ({@code fresh=false}). The row is then read back by its key WITHIN its domain, so a
     * retry returns the SAME persisted row (same DB-generated id) without a duplicate side
     * effect — and two brands sharing a subject string never collide.
     *
     * @return the persisted row, and whether THIS call inserted it ({@code fresh=true})
     *         or it already existed ({@code fresh=false} — a deduped retry).
     */
    public Mono<RecordedBan> recordBan(String dedupKey, String actor, String action, String platform,
                                       String target, String reason, String banType,
                                       LocalDateTime expiresAt, String propagationState) {
        return recordBan(dedupKey, actor, action, platform, target, reason, banType,
                expiresAt, propagationState, DEFAULT_DOMAIN);
    }

    /**
     * Domain-aware {@link #recordBan} — identical idempotent ON CONFLICT semantics, but
     * STAMPS the ban/lock row with the acting moderator's {@code domain} (issuer-derived
     * {@code DOMAIN_<x>}). A {@code null}/blank domain defensively falls back to
     * {@code "default"} so a ban row is never un-scoped.
     */
    public Mono<RecordedBan> recordBan(String dedupKey, String actor, String action, String platform,
                                       String target, String reason, String banType,
                                       LocalDateTime expiresAt, String propagationState, String domain) {
        return recordBan(dedupKey, actor, action, platform, target, reason, banType,
                expiresAt, propagationState, domain, null, null);
    }

    /**
     * Domain-aware {@link #recordBan} that ALSO stamps the service-scoped {@code @system}
     * notification directive (Notifications PR6): {@code notifyChannels} (a pre-scoped CSV
     * — see {@code NotifyDirective}) + {@code notifyEmailOnly}. Both nullable (null on the
     * non-notifying path + legacy rows). The directive describes the fan-out ONLY — it
     * never carries the acting mod identity.
     */
    public Mono<RecordedBan> recordBan(String dedupKey, String actor, String action, String platform,
                                       String target, String reason, String banType,
                                       LocalDateTime expiresAt, String propagationState, String domain,
                                       String notifyChannels, Boolean notifyEmailOnly) {
        LocalDateTime ts = LocalDateTime.now();
        String dom = domainOrDefault(domain);
        // result mirrors propagation_state for the ban surface (pending/applied/...). The id
        // is DB-generated (gen_random_uuid() DEFAULT, changelog 009): the INSERT omits it,
        // and ON CONFLICT DO NOTHING ... RETURNING id yields the new id on a FRESH insert and
        // NO row on a deduped conflict — so the presence of a returned id IS the fresh signal
        // (map(true)/defaultIfEmpty(false)) that the row-count formerly provided.
        return repo.insertBanReturningId(actor, action, platform, target, reason,
                        propagationState, ts, dedupKey, banType, expiresAt, propagationState, dom,
                        notifyChannels, notifyEmailOnly)
                .map(genId -> true)             // a returned id ⇒ THIS call inserted it (fresh)
                .defaultIfEmpty(false)          // no row returned ⇒ ON CONFLICT deduped (not fresh)
                // Read the row back DOMAIN-SCOPED (same resolved domain we stamped). With the
                // composite (dedup_key, domain) uniqueness this is at most one row; the domain
                // predicate is the belt-and-suspenders that a brand-Y read can NEVER surface a
                // brand-X row even if a key ever coincided (it no longer can — the key carries
                // the domain too). This is what closes the cross-tenant dedup-collision leak.
                // The persisted id comes from this read-back row (the DB-generated value),
                // whether THIS call or a prior delivery inserted it.
                .flatMap(fresh -> byDedupKey(dedupKey, dom)
                        .map(row -> new RecordedBan(row, fresh)));
    }

    /** Read a single ban row back by its dedup key (the idempotency lookup). UNSCOPED —
     *  legacy/back-compat single-tenant lookup; the cross-tenant-safe path is
     *  {@link #byDedupKey(String, String)} which the domain-aware {@link #recordBan}
     *  uses. */
    public Mono<ModAction> byDedupKey(String dedupKey) {
        return repo.findByDedupKey(dedupKey).map(ModActionRow::toModAction);
    }

    /** Read a single ban row back by its dedup key WITHIN {@code domain} (the
     *  cross-tenant-safe idempotency lookup). The {@code AND domain = :domain} predicate
     *  guarantees a brand-Y read-back never returns a brand-X row — the read-side half of
     *  closing the cross-tenant dedup-collision leak. FAIL-CLOSED on a {@code null} domain
     *  (an unprovable/ambiguous tenant): an empty {@link Mono}, never a global lookup. */
    public Mono<ModAction> byDedupKey(String dedupKey, String domain) {
        if (domain == null) return Mono.empty();                    // fail-closed: deny
        return repo.findByDedupKeyAndDomain(dedupKey, domain).map(ModActionRow::toModAction);
    }

    /** Defensive: a {@code null}/blank domain stamps {@code "default"} so a persisted
     *  row is NEVER un-scoped (an un-scoped row would be invisible to a scoped read and
     *  ambiguous to a cross-domain read — fail SAFE, scoped to the legacy tenant). */
    private static String domainOrDefault(String domain) {
        return (domain == null || domain.isBlank()) ? DEFAULT_DOMAIN : domain;
    }

    /** A persisted ban row + whether THIS call inserted it (vs a deduped retry). */
    public record RecordedBan(ModAction action, boolean fresh) {}
}
