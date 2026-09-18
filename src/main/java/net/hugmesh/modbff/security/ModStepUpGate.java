package net.hugmesh.modbff.security;

import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;

import net.hugmesh.modbff.web.StepUpRequiredException;

import java.util.List;

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

    /**
     * The step-up FLAVOUR this BFF advertises, in the platform's {@code X-<flavour>-StepUp}
     * spelling (admin-bff's gates each own one; {@code X-ImageGen-StepUp} is the reference).
     * It is the VALUE of the {@value StepUpRequiredException#SIGNAL_HEADER} response header on
     * a step-up refusal.
     *
     * <p><b>It is not a request header this service reads.</b> This gate has no token leg —
     * {@link #satisfied(Authentication)} consumes the {@code MFA_SATISFIED} marker authority
     * and nothing else — so the client's follow-up is a challenge that stamps the session
     * followed by a plain RETRY, not a token echoed back here. It is advertised so the flavour
     * is observable and so a future token leg needs no client change. See
     * {@link StepUpRequiredException} for the whole contract.
     */
    public static final String STEP_UP_HEADER = "X-Mod-StepUp";

    /**
     * One sensitive write-effect: the request shape that carries the step-up conjunct, plus
     * the verb that reads in its refusal message.
     *
     * @param method       the HTTP method of the mapping
     * @param pathPatterns every path template the mapping answers on, VERBATIM as
     *                     {@code ModController} spells them (trailing-slash variants included)
     * @param verb         the operation as it reads in the refusal, e.g. {@code "banning a user"}
     */
    public record SensitiveWrite(HttpMethod method, List<String> pathPatterns, String verb) {
        public SensitiveWrite {
            pathPatterns = List.copyOf(pathPatterns);
        }
    }

    /**
     * The FIVE sensitive write-effects, as request shapes.
     *
     * <p><b>Why this list exists at all.</b> {@link ModStepUpAccessDeniedHandler} has to decide
     * whether a 403 it is about to render was the STEP-UP leg failing or an ordinary role
     * refusal, and a denial carries no record of which conjunct said no. Scoping the signal to
     * exactly these request shapes — together with the handler's own check that the ROLE half
     * passed — is what stops a plain {@code ROLE_USER}'s bare role 403 on {@code POST
     * /bff/mod/block} from popping an MFA dialog that could not possibly help them.
     *
     * <p><b>It is a SECOND copy of a list whose first copy is the {@code @PreAuthorize}
     * annotations, so it can drift.</b> That is closed by
     * {@code ModStepUpConjunctInventoryTest}, which derives BOTH sets reflectively at runtime
     * (the annotation expressions on one side, this list on the other) and fails if they are
     * not equal — so a sixth gated endpoint that forgets this list, or an entry here with no
     * gate, is a red build rather than a silently unsignalled denial.
     */
    public static final List<SensitiveWrite> SENSITIVE_WRITES = List.of(
            new SensitiveWrite(HttpMethod.POST, List.of("/bff/mod/block"),
                    "blocking a user or instance server-wide"),
            new SensitiveWrite(HttpMethod.POST, List.of("/bff/mod/ban"),
                    "banning a user from a platform-access role"),
            new SensitiveWrite(HttpMethod.DELETE, List.of("/bff/mod/ban"),
                    "lifting a platform-access ban"),
            new SensitiveWrite(HttpMethod.POST,
                    List.of("/bff/mod/domain-lock/{role}/{user}", "/bff/mod/domain-lock/{role}/{user}/"),
                    "domain-locking a user"),
            new SensitiveWrite(HttpMethod.DELETE,
                    List.of("/bff/mod/domain-lock/{role}/{user}", "/bff/mod/domain-lock/{role}/{user}/"),
                    "domain-unlocking a user"));

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

    /**
     * The refusal to emit when {@link #satisfied(Authentication)} is false — the ONE place
     * this BFF's step-up flavour is bound to the platform exception, so a caller cannot
     * hand-roll a 403 that a client cannot recognise.
     *
     * <p>Deliberately SEPARATE from {@link #satisfied(Authentication)} rather than folded into
     * it: the predicate is called from a {@code @PreAuthorize} SpEL expression, and a boolean
     * that threw would be a side-effecting predicate whose exception escapes through the
     * authorization manager. Nothing about WHAT is denied moves — the conjunct still decides —
     * this only supplies the words and the flavour for the refusal
     * {@link ModStepUpAccessDeniedHandler} renders.
     *
     * @param verb the operation as it reads in the message, e.g. {@code "banning a user"}
     */
    public static StepUpRequiredException denial(String verb) {
        return StepUpRequiredException.forRetryHeader(STEP_UP_HEADER, verb);
    }
}
