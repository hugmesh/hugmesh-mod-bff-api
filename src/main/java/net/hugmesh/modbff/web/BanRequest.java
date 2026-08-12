package net.hugmesh.modbff.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

import java.util.List;
import java.util.Locale;

/**
 * Body for {@code POST /bff/mod/ban} — ban a user from a platform-access role. A ban
 * writes the {@code access_suspension} desired-state in admin-bff (the single-writer
 * reconcile loop applies it); mod-bff returns {@code 202 {state:'pending-reconcile'}}
 * and records a local {@code mod_action} row. A MOD may NOT ban a privileged user
 * ({@code ROLE_ADMIN}/{@code ROLE_MOD}) and may NOT ban themselves — those are 403s.
 *
 * <ul>
 *   <li>{@code platform} — {@code matrix} | {@code mastodon} | {@code profile}
 *       (case-insensitive); maps to the access role {@code ROLE_MATRIX} /
 *       {@code ROLE_MASTODON} / {@code PROFILE}.</li>
 *   <li>{@code target}   — the user being banned (Casdoor username / subject).</li>
 *   <li>{@code ttlSeconds} — OPTIONAL: null/absent = PERMANENT ban; a present value
 *       must be {@code @Positive} (auto-restore at TTL in admin-bff).</li>
 *   <li>{@code reason}   — OPTIONAL audit note (bounded).</li>
 *   <li>{@code idempotencyKey} — OPTIONAL client token making the ban DEDUP-able: the
 *       same token (or the same target with no token) collapses an at-least-once
 *       redelivery to one persisted action + one desired-state write. Supply a fresh
 *       token to intentionally re-ban a target after a lift.</li>
 *   <li>{@code notifyChannels} — OPTIONAL (Notifications PR6): the channels to notify the
 *       affected user on via the neutral {@code @system} sender. SERVICE-SCOPED to the
 *       action's {@code platform} ({@code in-app}/{@code email} always allowed; a
 *       platform-bound channel only when it matches {@code platform}). Each token is a
 *       bounded lower-alpha/hyphen channel name; the service drops anything off-scope.
 *       Ships dark.</li>
 *   <li>{@code notifyEmailOnly} — OPTIONAL: when true, force the notification to
 *       {@code email}+{@code in-app} ONLY (the conservative low-noise option), overriding
 *       {@code notifyChannels}. The directive NEVER carries the moderator's identity.</li>
 * </ul>
 */
public record BanRequest(
        @NotBlank(message = "platform is required")
        @Pattern(regexp = "(?i)matrix|mastodon|profile",
                message = "platform must be matrix, mastodon or profile")
        String platform,

        @NotBlank(message = "target is required")
        @Size(max = 400, message = "target is too long")
        String target,

        @Positive(message = "ttlSeconds must be a positive number of seconds")
        Long ttlSeconds,

        @Size(max = 2048, message = "reason is too long")
        String reason,

        @Size(max = 200, message = "idempotencyKey is too long")
        String idempotencyKey,

        @Size(max = 8, message = "at most 8 notify channels")
        List<@Pattern(regexp = "^[a-z][a-z-]{0,31}$",
                message = "channel must be a lower-alpha/hyphen token") String> notifyChannels,

        Boolean notifyEmailOnly) {

    /** Returns a defensive copy so callers cannot mutate the internal channel list. */
    @Override
    public List<String> notifyChannels() {
        return notifyChannels == null ? null : List.copyOf(notifyChannels);
    }

    /** Platform lower-cased to the canonical value (matrix|mastodon|profile). */
    public String platformLower() {
        return platform == null ? null : platform.toLowerCase(Locale.ROOT);
    }

    /** Whether email-only was requested (null → false). */
    public boolean emailOnly() {
        return Boolean.TRUE.equals(notifyEmailOnly);
    }
}
