package net.hugmesh.modbff.admin;

/**
 * The outcome of writing (or clearing) the {@code access_suspension} desired-state in
 * admin-bff. mod-bff does NOT apply the ban itself — it writes the DESIRED STATE via
 * the admin-bff {@code /bff/admin/access-roles/{role}/{user}} endpoint, and the
 * single-writer reconcile loop in admin-bff converges Casdoor + the homeserver. So
 * the only outcomes mod-bff can honestly report are:
 *
 * <ul>
 *   <li>{@link #PENDING} — the desired-state was written (or already present): the
 *       reconcile loop will apply it. This is the success path; the ban endpoint
 *       returns {@code 202 {state:'pending-reconcile'}} — NEVER a 200 "blocked",
 *       because the homeserver effect is asynchronous and may still be in flight.</li>
 *   <li>{@code degraded:<reason>} — the admin-bff call failed (breaker-open, timeout,
 *       5xx). The local {@code mod_action} row is still written so the intent is
 *       auditable; the caller surfaces a degraded 202, never a success.</li>
 * </ul>
 *
 * <p>There is deliberately NO {@code OK}/200-blocked outcome here: a write to the
 * desired-state table is not the same as the ban being enforced end-to-end.
 */
public record SuspensionOutcome(String state) {

    /** Desired-state written/confirmed; reconcile loop will apply. */
    public static final SuspensionOutcome PENDING = new SuspensionOutcome("pending-reconcile");

    public static SuspensionOutcome degraded(String reason) {
        return new SuspensionOutcome("degraded:" + reason);
    }

    public boolean isDegraded() {
        return state != null && state.startsWith("degraded:");
    }
}
