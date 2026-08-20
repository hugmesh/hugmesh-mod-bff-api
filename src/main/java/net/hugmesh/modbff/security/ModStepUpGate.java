package net.hugmesh.modbff.security;

import org.springframework.security.core.Authentication;

/**
 * STEP-UP (second-factor) gate for the SENSITIVE mod write-effects — the
 * {@code @PreAuthorize} companion of the role check on
 * {@code POST /bff/mod/block}, {@code POST|DELETE /bff/mod/ban} and
 * {@code POST|DELETE /bff/mod/domain-lock/{role}/{user}}. Those five are the
 * platform-wide / user-visible effects (a server-wide block, an access-role ban
 * or lift, a domain-lock or unlock); every other mod endpoint is a read or a
 * queue write and keeps the plain role gate.
 *
 * <p><b>How the second factor is proved.</b> This service can never MINT the
 * proof — it only CONSUMES the {@code MFA_SATISFIED} marker authority, which
 * both of this BFF's auth carriers already produce:
 * <ul>
 *   <li>a Casdoor JWT bearer — {@code CasdoorAuthorities} derives it from the
 *       freshness-validated {@link Roles#MFA_SATISFIED_AT_CLAIM} claim, but ONLY
 *       when {@code app.mfa.enabled} is true (see
 *       {@link net.hugmesh.modbff.config.SecurityConfig});</li>
 *   <li>an opaque {@code bff_} session — {@link
 *       net.hugmesh.modbff.auth.BffCookieAuthenticationWebFilter} adds it whenever
 *       admin-bff's introspect response reports {@code mfaSatisfied}, independently
 *       of {@code app.mfa.enabled}.</li>
 * </ul>
 * Reading the already-converted AUTHORITY (never a raw claim) is what keeps the
 * two carriers on one rule, and the converter's reserved-prefix guard is what makes
 * the marker unforgeable — a {@code permissions:["MFA_SATISFIED"]} is dropped.
 *
 * <p><b>Ships DARK, on its OWN sub-flag.</b> {@code app.mfa.enforce-sensitive-writes}
 * defaults {@code false}, so the gate returns {@code true} unconditionally and the
 * five endpoints behave byte-identically to before. The flag is deliberately SEPARATE
 * from {@code app.mfa.enabled} (which only governs DERIVATION) — exactly as the
 * gateway separates {@code app.mfa.enforce-privileged-floor} from it — because
 * enabling derivation must not silently start denying moderators. ⚠ On a JWT-carrier
 * deployment the two must be flipped TOGETHER: with {@code enforce-sensitive-writes=true}
 * but {@code enabled=false} the converter never emits the marker, so every gated call
 * 403s.
 *
 * <p>Once armed the gate is FAIL-CLOSED: a null {@link Authentication}, or one that
 * cannot prove a fresh second factor, is DENIED. There is no "unknown = allow" leg.
 */
public class ModStepUpGate {

    /** Whether the step-up requirement is ARMED ({@code app.mfa.enforce-sensitive-writes}). */
    private final boolean enforced;

    public ModStepUpGate(boolean enforced) {
        this.enforced = enforced;
    }

    /** True iff the step-up requirement is armed — exposed so a caller/test can tell
     *  "gate satisfied because MFA was proved" from "gate not armed at all". */
    public boolean isEnforced() {
        return enforced;
    }

    /**
     * The {@code @PreAuthorize} predicate: {@code true} when the sensitive write may
     * proceed. Dark (default) =&gt; always {@code true}; armed =&gt; ONLY when
     * {@code auth} carries the {@code MFA_SATISFIED} marker (fail-closed on null /
     * missing).
     */
    public boolean satisfied(Authentication auth) {
        if (!enforced) {
            return true;                 // dark default — byte-identical legacy behaviour
        }
        return Roles.isMfaSatisfied(auth);
    }
}
