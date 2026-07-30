package systems.hugmesh.modbff.federation;

/**
 * Body for {@code POST /api/federation/moderation}, matched field-for-field to
 * federation-api {@code ModerationController.SubmitRequest}:
 * {@code {kind, target, reason}}. The {@code requester} is NOT sent — federation-api
 * derives it from the forwarded JWT subject.
 *
 * <ul>
 *   <li>{@code kind} — {@code 'instance-block' | 'user-removal'} (validated
 *       server-side by federation-api).</li>
 * </ul>
 */
public record SubmitModerationRequest(String kind, String target, String reason) {}
