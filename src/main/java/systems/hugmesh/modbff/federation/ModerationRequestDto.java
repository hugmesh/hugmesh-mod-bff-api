package systems.hugmesh.modbff.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.time.Instant;

/**
 * Wire shape of a federation-api {@code moderation_requests} row, matched
 * FIELD-FOR-FIELD to hugmesh-federation-api
 * {@code systems.hugmesh.federation.model.ModerationRequest} (a JPA-style
 * entity whose Jackson serialisation uses its getters → these exact field names):
 * {@code id, requester, kind, target, reason, status, modReferrer, adminDecider,
 * ts}.
 *
 * <ul>
 *   <li>{@code kind}   — {@code 'instance-block' | 'user-removal'}</li>
 *   <li>{@code status} — {@code 'recommended' | 'referred' | 'approved' | 'denied'}</li>
 * </ul>
 *
 * <p>A record (immutable DTO) on the BFF side; {@code @JsonIgnoreProperties} keeps
 * us forward-compatible if federation-api adds a field.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record ModerationRequestDto(
        Long id,
        String requester,
        String kind,
        String target,
        String reason,
        String status,
        String modReferrer,
        String adminDecider,
        Instant ts
) {}
