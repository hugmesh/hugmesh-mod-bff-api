package net.hugmesh.modbff.external;

/**
 * The outcome of a server-wide block attempt against an external homeserver
 * (tuwunel / akkoma). Carried back to the controller so it can be recorded in the
 * {@code mod_action} audit row's {@code result} column and surfaced to the mod-ui.
 *
 * <ul>
 *   <li>{@link #STUBBED} — the external admin HTTP call is deliberately NOT made:
 *       either the target is tuwunel (no Synapse-style admin REST API at all — this
 *       leg is unconditionally stubbed, see {@code MatrixAdminClient}) or the target
 *       is akkoma with {@code external.mastodon.enabled=false} (the platform default
 *       — the pleroma-admin call shape itself IS confirmed/pinned in code, it is just
 *       gated dark until enabled, see {@code MastodonAdminClient}). The action is
 *       still audited locally. See README "Honest deferrals".</li>
 *   <li>{@link #OK} — the external call was made and succeeded (only when an
 *       integration is wired + enabled).</li>
 *   <li>{@code degraded:<reason>} — the external call was attempted and failed;
 *       use {@link #degraded(String)}.</li>
 * </ul>
 */
public record BlockOutcome(String result) {

    public static final BlockOutcome STUBBED = new BlockOutcome("stubbed");
    public static final BlockOutcome OK = new BlockOutcome("ok");

    public static BlockOutcome degraded(String reason) {
        return new BlockOutcome("degraded:" + reason);
    }

    public boolean isStubbed() {
        return "stubbed".equals(result);
    }

    /**
     * True ONLY when the external homeserver block actually landed ({@link #OK}). A
     * {@code stubbed} or {@code degraded:<reason>} (breaker-open / error) outcome is
     * NOT ok — the caller must then return {@code 202 pending-reconcile}, never a 200
     * "blocked", because the effect was not applied.
     */
    public boolean isOk() {
        return "ok".equals(result);
    }
}
