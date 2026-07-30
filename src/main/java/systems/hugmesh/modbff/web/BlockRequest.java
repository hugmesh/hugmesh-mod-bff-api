package systems.hugmesh.modbff.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.util.Locale;

/**
 * Body for {@code POST /bff/mod/block} — block a user/instance server-wide on
 * Matrix/Mastodon. Replaces the previous untyped {@code Map<String,Object>} with a
 * validated DTO so a bad {@code platform}/{@code scope} or a missing {@code target}
 * is rejected with a clean 400 (matching the enum membership the DB now also
 * enforces via the {@code ck_mod_action_platform} CHECK).
 *
 * <ul>
 *   <li>{@code platform} — {@code matrix} | {@code mastodon} (case-insensitive).</li>
 *   <li>{@code scope}    — {@code user} | {@code instance} (case-insensitive).</li>
 *   <li>{@code target}   — the MXID / acct / instance domain being acted on.</li>
 *   <li>{@code reason}   — optional free-text justification (bounded).</li>
 * </ul>
 */
public record BlockRequest(
        @NotBlank(message = "platform is required")
        @Pattern(regexp = "(?i)matrix|mastodon", message = "platform must be matrix or mastodon")
        String platform,

        @NotBlank(message = "scope is required")
        @Pattern(regexp = "(?i)user|instance", message = "scope must be user or instance")
        String scope,

        @NotBlank(message = "target is required")
        @Size(max = 512, message = "target is too long")
        String target,

        @Size(max = 2048, message = "reason is too long")
        String reason) {

    /** Platform lower-cased to the canonical audit/enum value. */
    public String platformLower() { return platform == null ? null : platform.toLowerCase(Locale.ROOT); }

    /** Scope lower-cased to the canonical value. */
    public String scopeLower() { return scope == null ? null : scope.toLowerCase(Locale.ROOT); }
}
