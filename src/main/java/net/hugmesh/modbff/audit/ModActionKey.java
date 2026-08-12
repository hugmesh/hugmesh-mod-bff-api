package net.hugmesh.modbff.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;

/**
 * Builds the DETERMINISTIC client dedup / idempotency key stored in
 * {@code mod_action.dedup_key}. The ban write path (the admin-bff access-suspension
 * submit + the homeserver propagation) is at-least-once, so the SAME logical ban
 * must map to the SAME key — a redelivery then dedups against the partial unique
 * index ({@link ModActionRepository#recordBan}) instead of double-effecting.
 *
 * <p>The key is a SHA-256 over the stable identity of the action
 * ({@code action|role|target|actor|domain}) joined with an explicit client-supplied
 * idempotency token when present. A caller that wants two genuinely distinct bans
 * of the same target (e.g. re-ban after a lift) supplies a fresh idempotency token;
 * a retry of the SAME request supplies the same token (or none, in which case the
 * action/role/target/actor/domain tuple is the key and an immediate accidental
 * re-submit is absorbed).
 *
 * <p>MULTI-TENANT ISOLATION: the {@code domain} (the acting moderator's
 * issuer-derived brand, the SAME value stamped on the persisted row) is part of the
 * key material so two brands' Casdoor minting the SAME subject string (e.g. both
 * "alice") banning the same target+role with NO client idempotency token can NEVER
 * produce the same dedup key — without it, brand-Y's ban would collide with
 * brand-X's row (ON CONFLICT DO NOTHING), leak brand-X's audit row back into
 * brand-Y's response, AND silently swallow brand-Y's effect. The composite
 * {@code (dedup_key, domain)} uniqueness + the domain-scoped read are the
 * belt-and-suspenders to this key-level separation.
 */
public final class ModActionKey {

    private ModActionKey() {}

    /**
     * Deterministic key for an access-role ban/lift, SCOPED to the acting moderator's
     * brand/domain so two brands never collide on a shared subject string.
     *
     * @param action        {@code access.suspend} | {@code access.restore}
     * @param role          the access role ({@code ROLE_MATRIX} / {@code ROLE_MASTODON} / {@code PROFILE})
     * @param target        the user being banned/lifted
     * @param actor         the acting moderator (so two mods' independent actions never collide)
     * @param domain        the acting moderator's issuer-derived brand/domain (the SAME value
     *                      stamped on the row) — keeps two brands' identical subject strings apart
     * @param idempotencyKey optional client token; blank/null falls back to the tuple above
     */
    public static String ban(String action, String role, String target, String actor,
                             String domain, String idempotencyKey) {
        String token = (idempotencyKey == null || idempotencyKey.isBlank()) ? "" : idempotencyKey.trim();
        String material = String.join("|",
                nv(action), nv(role), nv(target), nv(actor), nv(domain), token);
        return sha256(material);
    }

    private static String nv(String s) {
        return s == null ? "" : s;
    }

    private static String sha256(String material) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(material.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (Exception e) {
            // SHA-256 is a JCE baseline algorithm — unreachable on any supported JVM.
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
