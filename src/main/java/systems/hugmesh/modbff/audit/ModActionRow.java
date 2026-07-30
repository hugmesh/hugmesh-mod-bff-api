package systems.hugmesh.modbff.audit;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Relational (R2DBC) entity for the BFF's OWN {@code mod_action} audit table (schema
 * in Liquibase {@code db/changelog/001-mod-action.xml} through {@code 008-...}). One
 * row per moderator action. The column set + types match the changelog EXACTLY:
 *
 * <ul>
 *   <li>{@code id}                — uuid PK (001), DB-generated (gen_random_uuid()
 *                                   DEFAULT, 009) and read back via RETURNING id.</li>
 *   <li>{@code actor}            — varchar(255) NOT NULL (001).</li>
 *   <li>{@code action}           — varchar(64) NOT NULL (001), CHECK-constrained.</li>
 *   <li>{@code platform}         — varchar(32) NOT NULL (001), CHECK-constrained.</li>
 *   <li>{@code target}           — varchar(512) NOT NULL (001), reserved word.</li>
 *   <li>{@code reason}           — varchar(2048) nullable (001).</li>
 *   <li>{@code result}           — varchar(255) NOT NULL (001).</li>
 *   <li>{@code ts}               — timestamp NOT NULL (001), app-stamped.</li>
 *   <li>{@code dedupKey}         — varchar(255) nullable (003).</li>
 *   <li>{@code banType}          — varchar(32) nullable (003).</li>
 *   <li>{@code expiresAt}        — timestamp nullable (003).</li>
 *   <li>{@code propagationState} — varchar(16) nullable (003).</li>
 *   <li>{@code domain}           — varchar(64) NOT NULL DEFAULT 'default' (005).</li>
 *   <li>{@code notifyChannels}   — varchar(256) nullable (008).</li>
 *   <li>{@code notifyEmailOnly}  — boolean nullable (008).</li>
 * </ul>
 *
 * <p>Stays a RECORD per the data-access standard. The id is DB-generated (a
 * {@code gen_random_uuid()} column DEFAULT, changelog 009), so inserts go through the
 * repository's explicit {@code INSERT ... RETURNING id} {@code @Query} (which also gives
 * the ban path its {@code ON CONFLICT DO NOTHING} idempotency); the derived SELECT
 * finders map rows back into this entity. The public-facing
 * {@link ModAction} record is the API/DTO shape; {@link ModActionRepository} converts
 * between the two so callers/tests are unchanged.
 */
@Table("mod_action")
public record ModActionRow(
        @Id
        @Column("id")
        UUID id,
        @Column("actor")
        String actor,
        @Column("action")
        String action,
        @Column("platform")
        String platform,
        @Column("target")
        String target,
        @Column("reason")
        String reason,
        @Column("result")
        String result,
        @Column("ts")
        LocalDateTime ts,
        @Column("dedup_key")
        String dedupKey,
        @Column("ban_type")
        String banType,
        @Column("expires_at")
        LocalDateTime expiresAt,
        @Column("propagation_state")
        String propagationState,
        @Column("domain")
        String domain,
        @Column("notify_channels")
        String notifyChannels,
        @Column("notify_email_only")
        Boolean notifyEmailOnly
) {

    /** Convert to the API/DTO {@link ModAction} (UUID id rendered as its String form,
     *  matching the legacy {@code DatabaseClient} mapping which did
     *  {@code row.get("id").toString()}). */
    ModAction toModAction() {
        return new ModAction(
                id == null ? null : id.toString(),
                actor, action, platform, target, reason, result, ts,
                dedupKey, banType, expiresAt, propagationState, domain,
                notifyChannels, notifyEmailOnly);
    }
}
