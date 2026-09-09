package net.hugmesh.modbff.external;

/**
 * The outcome of a server-wide block attempt against an external homeserver
 * (tuwunel / akkoma). Carried back to the controller so it can be recorded in the
 * {@code mod_action} audit row's {@code result} column and surfaced to the mod-ui.
 *
 * <ul>
 *   <li>{@link #STUBBED} — the external admin call is deliberately NOT made because
 *       the integration is disabled ({@code external.{matrix,mastodon}.enabled=false},
 *       the platform default — see {@code MatrixAdminClient} / {@code MastodonAdminClient}).
 *       The action is still audited locally. See README "Honest deferrals".</li>
 *   <li>{@link #OK} — the external call was made and the effect is known to have
 *       landed (only when an integration is wired + enabled).</li>
 *   <li>{@code posted:<event_id>} — tuwunel only: the {@code !admin} command MESSAGE
 *       was accepted into the admin room (event id recorded) but the bot applies it
 *       asynchronously and its reply is not yet correlated, so the effect is
 *       unconfirmed. NOT ok — the caller stays 202 pending. Use {@link #posted(String)}.</li>
 *   <li>{@code degraded:<reason>} — the external call was attempted and failed, or
 *       could not be attempted for a named reason (no admin token, no tuwunel verb);
 *       use {@link #degraded(String)}.</li>
 * </ul>
 */
public record BlockOutcome(String result) {

    public static final BlockOutcome STUBBED = new BlockOutcome("stubbed");
    public static final BlockOutcome OK = new BlockOutcome("ok");

    public static BlockOutcome degraded(String reason) {
        return new BlockOutcome("degraded:" + reason);
    }

    /** The admin-room command was posted (event id recorded); the effect is asynchronous and unconfirmed. */
    public static BlockOutcome posted(String eventId) {
        return new BlockOutcome("posted:" + eventId);
    }

    public boolean isStubbed() {
        return "stubbed".equals(result);
    }

    /** True when the command message was accepted into the admin room but the effect is not yet confirmed. */
    public boolean isPosted() {
        return result != null && result.startsWith("posted:");
    }

    /**
     * True ONLY when the external homeserver block actually landed ({@link #OK}). A
     * {@code stubbed}, {@code posted:<event_id>} (effect unconfirmed) or
     * {@code degraded:<reason>} (breaker-open / error) outcome is NOT ok — the caller
     * must then return {@code 202 pending-reconcile}, never a 200 "blocked", because
     * the effect was not (yet) known to be applied.
     */
    public boolean isOk() {
        return "ok".equals(result);
    }
}
