package net.hugmesh.modbff.web;

import jakarta.validation.constraints.Size;
import org.springframework.lang.Nullable;

/**
 * OPTIONAL body for {@code POST /bff/mod/owncast/streams/{ownerSubject}/hide|kill|restore}
 * — the target travels as a PATH variable (matching the owncast-bff moderation surface),
 * so this body only carries the optional metadata:
 *
 * <ul>
 *   <li>{@code reason} — OPTIONAL audit note (bounded), recorded on the central
 *       {@code mod_action} ledger row AND forwarded to owncast-bff (which journals it
 *       into its local {@code owncast_moderation_audit}).</li>
 * </ul>
 *
 * <p>The body is entirely optional — a bare {@code POST} moderates with no reason. No
 * idempotency token: the owncast effect is synchronous and idempotent at owncast-bff
 * (a re-kill of an already-banned owner / a re-hide of an internal stream is a no-op
 * there), unlike the at-least-once desired-state writes the ban/lock surfaces dedup.
 */
public record OwncastModRequest(
        @Size(max = 2048, message = "reason is too long")
        @Nullable
        String reason) {
}
