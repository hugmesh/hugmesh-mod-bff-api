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
 *   <li>{@code degraded:<reason>} — the external call was attempted and FAILED (or
 *       could not be attempted) for an operational reason (no admin token, breaker
 *       open, a non-2xx response); use {@link #degraded(String)}. A transient/error
 *       condition — retrying later, or fixing the operational cause, can resolve it.</li>
 *   <li>{@code requested:<reason>} — NOT an error: no external call was attempted
 *       because none can apply the effect synchronously by design (e.g. tuwunel has no
 *       runtime whole-server federation-block verb), so the intent is recorded as a
 *       durable REQUEST for a human/GitOps process to apply out of band. Distinct from
 *       {@code degraded} so a reader (an operator scanning {@code mod_action}, or the
 *       mod-ui note) never mistakes "nothing can apply this automatically" for "this
 *       failed and might succeed on retry"; use {@link #requested(String)}.</li>
 *   <li>{@code domain-locked} — tuwunel-specific: a MOD-initiated Matrix USER block
 *       was NOT posted as the (irreversible) {@code !admin users deactivate} command —
 *       it was written as the REVERSIBLE {@code domain_lock} desired-state instead
 *       (operator decision 51, 2026-09-18; see {@code ModService#matrixUserBlock}). Use
 *       {@link #DOMAIN_LOCKED}.</li>
 * </ul>
 */
public record BlockOutcome(String result) {

    public static final BlockOutcome STUBBED = new BlockOutcome("stubbed");
    public static final BlockOutcome OK = new BlockOutcome("ok");
    /** See the {@code domain-locked} entry above. */
    public static final BlockOutcome DOMAIN_LOCKED = new BlockOutcome("domain-locked");

    public static BlockOutcome degraded(String reason) {
        return new BlockOutcome("degraded:" + reason);
    }

    /**
     * See the {@code requested:<reason>} entry above — a durably-recorded request, not
     * an attempted-and-failed effect. NEVER {@link #isOk() ok} and never implies the
     * effect was applied.
     */
    public static BlockOutcome requested(String reason) {
        return new BlockOutcome("requested:" + reason);
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

    /** True when the intent was durably recorded as a REQUEST for a human/GitOps process,
     *  because nothing here can apply the effect synchronously — never {@link #isOk()}. */
    public boolean isRequested() {
        return result != null && result.startsWith("requested:");
    }

    /** True when a MOD-initiated Matrix user block was applied as the reversible
     *  domain-lock effect rather than the one-way deactivate transport. */
    public boolean isDomainLocked() {
        return "domain-locked".equals(result);
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
