package net.hugmesh.modbff.web;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Body for {@code POST /bff/mod/moderation} — record a moderation recommendation
 * into the federation queue (the user→mod→admin chain's middle step). Replaces the
 * previous untyped {@code Map<String,Object>}: {@code kind} + {@code target} are
 * required, {@code reason} optional.
 *
 * <p>{@code kind} is {@code instance-block} | {@code user-removal} — the same closed
 * vocabulary federation-api validates server-side ({@code ModerationController}).
 * We bound it here so a malformed kind is a clean 400 at the BFF edge before the
 * federation call; federation-api remains the authority.
 */
public record RecommendRequest(
        @NotBlank(message = "kind is required")
        @Pattern(regexp = "instance-block|user-removal",
                message = "kind must be instance-block or user-removal")
        String kind,

        @NotBlank(message = "target is required")
        @Size(max = 512, message = "target is too long")
        String target,

        @Size(max = 2048, message = "reason is too long")
        String reason) {
}
