package net.hugmesh.modbff.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;

/**
 * Wire shape of a federation-api {@code system_findings} row, matched
 * FIELD-FOR-FIELD to hugmesh-federation-api
 * {@code net.hugmesh.federation.model.SystemFinding} (whose Jackson
 * serialisation uses its getters → these exact field names): {@code id, reporter,
 * subject, surface, disposition, classification, confidence, policyHit,
 * perceptualHash, status, reviewer, ts, domain}.
 *
 * <p>A system finding is filed AUTOMATICALLY by an upstream edge-AI moderation
 * check (the pre-publish avatar/image vision moderation: user-bff → federation
 * {@code POST /api/federation/findings}) and lands {@code held} for a human
 * moderator to LIST + RESOLVE — which is exactly the surface this BFF proxies to
 * the moderator UI. The companion HUMAN recommend/refer/decide workflow is the
 * separate {@link ModerationRequestDto} queue.
 *
 * <ul>
 *   <li>{@code reporter}    — always {@code @system} (the automated origin);</li>
 *   <li>{@code subject}     — the content owner (Casdoor subject) whose image was
 *       flagged (server-derived on the producer side, never a body field);</li>
 *   <li>{@code surface}     — where the content was set ({@code profile-avatar}, ...);</li>
 *   <li>{@code disposition} — {@code flagged} (published, queued) | {@code rejected}
 *       (blocked at upload);</li>
 *   <li>{@code status}      — {@code held} (awaiting review) | {@code dismissed}
 *       (mod cleared it) | {@code actioned} (mod took action);</li>
 *   <li>classification / confidence / policyHit / perceptualHash — the edge-AI verdict;</li>
 *   <li>{@code reviewer}    — the mod/admin who resolved it (null while {@code held});</li>
 *   <li>{@code domain}      — the brand this finding belongs to (multi-tenancy; the
 *       federation list is already issuer-domain-scoped server-side).</li>
 * </ul>
 *
 * <p>A record (immutable DTO) on the BFF side; {@code @JsonIgnoreProperties} keeps
 * us forward-compatible if federation-api adds a field.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SystemFindingDto(
        Long id,
        String reporter,
        String subject,
        String surface,
        String disposition,
        String classification,
        Double confidence,
        Boolean policyHit,
        String perceptualHash,
        String status,
        String reviewer,
        Instant ts,
        String domain
) {}
