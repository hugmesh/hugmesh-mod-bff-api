package net.hugmesh.modbff.web;

import jakarta.validation.constraints.Size;

/**
 * OPTIONAL body for {@code POST/DELETE /bff/mod/domain-lock/{role}/{user}} — the
 * {@code role} and {@code user} travel as PATH variables (matching the admin-bff
 * domain-lock surface), so this body only carries the optional metadata:
 *
 * <ul>
 *   <li>{@code reason} — OPTIONAL audit note (bounded), recorded on the
 *       {@code mod_action} row and forwarded to admin-bff on a LOCK.</li>
 *   <li>{@code idempotencyKey} — OPTIONAL client token making the lock/unlock
 *       DEDUP-able: the same token (or the same role+target with no token) collapses an
 *       at-least-once redelivery to one persisted action + one desired-state write.</li>
 * </ul>
 *
 * <p>The body is entirely optional — a bare {@code POST}/{@code DELETE} with no body
 * domain-locks/unlocks with no reason and tuple-based dedup. The controller defaults a
 * missing body to an empty instance.
 */
public record DomainLockRequest(
        @Size(max = 2048, message = "reason is too long")
        String reason,

        @Size(max = 200, message = "idempotencyKey is too long")
        String idempotencyKey) {

    /** An empty request (no reason / no idempotency token) for a body-less call. */
    public static DomainLockRequest empty() {
        return new DomainLockRequest(null, null);
    }
}
