package net.hugmesh.modbff.audit;

import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Reactive (R2DBC) Spring Data repository for the {@code mod_action} audit table.
 * Matches the hugmesh-federation-api reactive-repository idiom: an interface
 * extending {@link ReactiveCrudRepository} with DERIVED query methods first, and an
 * explicit {@link Query} only where derivation cannot express the statement — here the
 * two INSERTs and, critically, the ban path's {@code ON CONFLICT DO NOTHING} idempotency
 * upsert. Every {@code @Query} SQL is a {@code static final String} CONSTANT — never an
 * inline literal — per the data-access standard.
 *
 * <p>DB-GENERATED UUID PK (the org-wide migration exemplar): the {@code id} is NO LONGER
 * minted in Java. The {@code mod_action.id} column carries a
 * {@code DEFAULT gen_random_uuid()} (pgcrypto, changelog 009), so each INSERT OMITS
 * {@code id} and appends {@code RETURNING id} to read the database-generated UUID back.
 * The two INSERTs are therefore plain {@code @Query} SELECT-shaped statements returning
 * {@code Mono<UUID>} (NOT {@code @Modifying} row counts): the plain insert always
 * RETURNs the new id; the {@code ON CONFLICT DO NOTHING} insert RETURNs the new id on a
 * fresh insert and NO row (an empty {@code Mono}) on a deduped conflict — which is
 * exactly the fresh-vs-deduped signal the caller needs.
 *
 * <p>The {@link ModActionRepository} facade is the only caller; it converts between
 * {@link ModActionRow} (entity) and {@link ModAction} (API/DTO) and preserves the
 * original public method shapes so controllers/services/tests are unchanged.
 */
public interface ModActionR2dbcRepository extends ReactiveCrudRepository<ModActionRow, UUID> {

    // -- BOUNDED audit-trail SELECTs (static-final SQL constants; an explicit
    //    {@code ORDER BY ts DESC LIMIT :limit} CAPS the unbounded read). The four
    //    {@code GET /bff/mod/audit} finder variants each carry a hard server-clamped
    //    {@code :limit} so a moderator's audit read can NEVER stream the whole
    //    {@code mod_action} table into memory (the unbounded-table DoS). The {@code ts}
    //    DESC ordering is preserved exactly (newest-first, the legacy contract), so the
    //    LIMIT keeps the MOST-RECENT N rows. Each predicate (actor/domain) is preserved
    //    verbatim so the cross-tenant scoping semantics are unchanged. Derivation cannot
    //    express a parameterized LIMIT, so these are explicit {@code @Query} constants per
    //    the data-access standard.

    /** UNSCOPED, newest-first, CAPPED at {@code :limit} (the SUPERADMIN {@code list()}). */
    String SELECT_ALL_NEWEST_LIMIT = """
            SELECT * FROM mod_action \
            ORDER BY ts DESC \
            LIMIT :limit""";

    /** Per-actor, newest-first, CAPPED (the SUPERADMIN {@code listByActor}). */
    String SELECT_BY_ACTOR_NEWEST_LIMIT = """
            SELECT * FROM mod_action \
            WHERE actor = :actor \
            ORDER BY ts DESC \
            LIMIT :limit""";

    /** Per-domain, newest-first, CAPPED (the per-brand {@code listForDomain}). */
    String SELECT_BY_DOMAIN_NEWEST_LIMIT = """
            SELECT * FROM mod_action \
            WHERE domain = :domain \
            ORDER BY ts DESC \
            LIMIT :limit""";

    /** Per-actor-and-domain, newest-first, CAPPED (the per-brand {@code listByActorForDomain}). */
    String SELECT_BY_ACTOR_AND_DOMAIN_NEWEST_LIMIT = """
            SELECT * FROM mod_action \
            WHERE actor = :actor AND domain = :domain \
            ORDER BY ts DESC \
            LIMIT :limit""";

    /** Bounded UNSCOPED audit read, newest first, capped at {@code :limit} rows
     *  (legacy {@code list()}). */
    @Query(SELECT_ALL_NEWEST_LIMIT)
    Flux<ModActionRow> findNewest(@Param("limit") int limit);

    /** Bounded per-actor audit read, newest first, capped (legacy {@code listByActor}). */
    @Query(SELECT_BY_ACTOR_NEWEST_LIMIT)
    Flux<ModActionRow> findByActorNewest(@Param("actor") String actor, @Param("limit") int limit);

    /** Bounded per-domain audit read, newest first, capped (legacy {@code listForDomain}). */
    @Query(SELECT_BY_DOMAIN_NEWEST_LIMIT)
    Flux<ModActionRow> findByDomainNewest(@Param("domain") String domain, @Param("limit") int limit);

    /** Bounded per-actor-and-domain audit read, newest first, capped
     *  (legacy {@code listByActorForDomain}). */
    @Query(SELECT_BY_ACTOR_AND_DOMAIN_NEWEST_LIMIT)
    Flux<ModActionRow> findByActorAndDomainNewest(@Param("actor") String actor,
                                                  @Param("domain") String domain,
                                                  @Param("limit") int limit);

    // -- DERIVED point reads (no SQL string): the ban dedup read-backs (single row).

    /** {@code ... WHERE dedup_key = :dedup_key} (legacy unscoped {@code byDedupKey}). */
    Mono<ModActionRow> findByDedupKey(String dedupKey);

    /** {@code ... WHERE dedup_key = :dedup_key AND domain = :domain} (legacy domain-scoped
     *  {@code byDedupKey(key, domain)} read-back). */
    Mono<ModActionRow> findByDedupKeyAndDomain(String dedupKey, String domain);

    // -- EXPLICIT INSERTs (static-final SQL constants; derivation cannot express an
    //    INSERT ... RETURNING or an ON CONFLICT DO NOTHING upsert). The id is OMITTED —
    //    the database fills it from its gen_random_uuid() DEFAULT (changelog 009) — and
    //    RETURNING id reads the generated UUID back.

    /**
     * The {@code record(...)} INSERT: DB-generated id + app-stamped ts, 8 supplied
     * columns. The {@code id} is OMITTED so Postgres fills it from the
     * {@code gen_random_uuid()} column DEFAULT; {@code RETURNING id} reads the generated
     * UUID back. A plain (non-{@code @Modifying}) {@code @Query} returning the new id.
     */
    String INSERT_ACTION_RETURNING_ID = """
            INSERT INTO mod_action \
            (actor, action, platform, target, reason, result, ts, domain) \
            VALUES (:actor, :action, :platform, :target, :reason, :result, :ts, :domain) \
            RETURNING id""";

    /**
     * The {@code recordBan(...)} idempotent INSERT: DB-generated id + app-stamped ts, the
     * full ban-shape + notify column set, with {@code ON CONFLICT DO NOTHING} (no explicit
     * conflict target — the only index that can fire is the composite
     * {@code uq_mod_action_dedup_key_domain}, so a redelivery with the same
     * {@code (dedup_key, domain)} inserts 0 rows). The {@code id} is OMITTED (filled from
     * the {@code gen_random_uuid()} DEFAULT); {@code RETURNING id} yields the generated id
     * ON A FRESH INSERT and NO ROW on a deduped conflict (a 0-row insert RETURNs nothing) —
     * so the caller reads a present id ⇒ {@code fresh=true}, an empty {@code Mono} ⇒
     * {@code fresh=false}.
     */
    String INSERT_BAN_ON_CONFLICT_DO_NOTHING_RETURNING_ID = """
            INSERT INTO mod_action \
            (actor, action, platform, target, reason, result, ts, \
             dedup_key, ban_type, expires_at, propagation_state, domain, \
             notify_channels, notify_email_only) \
            VALUES (:actor, :action, :platform, :target, :reason, :result, :ts, \
             :dedup_key, :ban_type, :expires_at, :propagation_state, :domain, \
             :notify_channels, :notify_email_only) \
            ON CONFLICT DO NOTHING \
            RETURNING id""";

    /** The plain INSERT ... RETURNING id — always yields the DB-generated UUID. */
    @Query(INSERT_ACTION_RETURNING_ID)
    Mono<UUID> insertActionReturningId(@Param("actor") String actor,
                                       @Param("action") String action,
                                       @Param("platform") String platform,
                                       @Param("target") String target,
                                       @Param("reason") String reason,
                                       @Param("result") String result,
                                       @Param("ts") LocalDateTime ts,
                                       @Param("domain") String domain);

    /** The idempotent INSERT ... ON CONFLICT DO NOTHING RETURNING id — yields the new id
     *  on a fresh insert, EMPTY on a deduped conflict (RETURNING yields no row when 0 rows
     *  are inserted). */
    @Query(INSERT_BAN_ON_CONFLICT_DO_NOTHING_RETURNING_ID)
    Mono<UUID> insertBanReturningId(@Param("actor") String actor,
                                    @Param("action") String action,
                                    @Param("platform") String platform,
                                    @Param("target") String target,
                                    @Param("reason") String reason,
                                    @Param("result") String result,
                                    @Param("ts") LocalDateTime ts,
                                    @Param("dedup_key") String dedupKey,
                                    @Param("ban_type") String banType,
                                    @Param("expires_at") LocalDateTime expiresAt,
                                    @Param("propagation_state") String propagationState,
                                    @Param("domain") String domain,
                                    @Param("notify_channels") String notifyChannels,
                                    @Param("notify_email_only") Boolean notifyEmailOnly);
}
