package net.hugmesh.modbff.web;

import org.springframework.http.HttpStatus;
import net.hugmesh.commons.web.ApiException;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * The ONE place that mints a "step-up required" refusal in this BFF, and the ONE place that
 * owns the structured signal telling a client <em>which</em> step-up flavour to satisfy.
 *
 * <h2>Why this exists</h2>
 * Before this type, {@link net.hugmesh.modbff.security.ModStepUpGate} denied through a
 * {@code @PreAuthorize} conjunct, so a step-up refusal was indistinguishable on the wire from
 * any other authorization refusal: both were a bare Spring {@code AccessDeniedException} 403
 * with no body and no header. hugmesh-mod-ui shipped the whole client half of the flow
 * (a detection predicate {@code src/app/mfa/step-up-error.ts}, an {@code MfaService}, and the
 * {@code MfaStepUpDialogComponent} wired in front of ban / lift / domain-lock / unlock /
 * block) and it was INERT — not because the client was wrong, but because neither of its
 * detection legs could fire against the denial this service sent. See hugmesh-mod-bff-api#16.
 *
 * <h2>The wire contract</h2>
 * Deliberately byte-compatible with hugmesh-admin-bff-api's
 * {@code net.hugmesh.adminbff.web.StepUpRequiredException}, which is the platform reference
 * emitter — one contract across BFFs, not one per repo:
 * <ul>
 *   <li><b>Status stays 403.</b> Deliberately NOT 428: every existing client branches on 403,
 *       and a status change would be a breaking, non-rolling-deployable change. (mod-ui
 *       happens to accept 428 as well, but nothing on the platform emits it.)</li>
 *   <li><b>Body is the unchanged {@code {"error": "<message>"}}</b> that
 *       {@link ApiExceptionHandler} has always emitted for EVERY {@link ApiException}.
 *       Nothing is added to the shared JSON error body, so no unrelated error's wire shape
 *       moves.</li>
 *   <li><b>The signal is a response header</b>, {@value #SIGNAL_HEADER}, whose value names the
 *       step-up FLAVOUR in the platform's {@code X-<flavour>-StepUp} spelling — here
 *       {@link net.hugmesh.modbff.security.ModStepUpGate#STEP_UP_HEADER}. Absent on every
 *       non-step-up response, which is what keeps a routine role DENY from popping an MFA
 *       prompt in the browser.</li>
 * </ul>
 *
 * <h2>What the signal value means HERE — read this before plumbing a token</h2>
 * On admin-bff the value is the name of a request header the retry must carry a single-use
 * step-up TOKEN in. <b>This BFF has no token leg at all.</b>
 * {@code ModStepUpGate.satisfied(auth)} is {@code Roles.isMfaSatisfied(auth)} and nothing
 * else — it consumes the {@code MFA_SATISFIED} marker authority that the JWT converter or
 * admin-bff's introspect response already produced. So the correct client follow-up is:
 * complete a challenge (which stamps the caller's session / next token), then RETRY the same
 * request unchanged. Sending {@value #SIGNAL_HEADER}'s value back as a request header is
 * harmless and ignored. mod-ui already documents exactly this
 * ({@code step-up-error.ts}, {@code StepUpRequirement.retryHeader}), and this is the same
 * shape hugmesh-forum-bff-api#15 proposes for its own gate. The value is carried anyway so
 * the flavour is OBSERVABLE rather than discarded, and so a future token leg needs no client
 * change.
 *
 * <h2>Backward compatibility in BOTH directions (rolling deploy)</h2>
 * <ul>
 *   <li><b>old client + new server:</b> the free-text phrase {@value #LEGACY_PHRASE} is
 *       carried in every message. {@link #LEGACY_PHRASE} is the single place main sources
 *       EMIT that literal, so it cannot drift out from under a client that greps for it —
 *       mod-ui's {@code LEGACY_STEP_UP_PATTERN} is {@code /requires step-up/i}.</li>
 *   <li><b>new client + old server:</b> a client that reads the header keeps the phrase sniff
 *       as a fallback; mod-ui does.</li>
 * </ul>
 *
 * @see ApiExceptionHandler
 * @see net.hugmesh.modbff.security.ModStepUpGate
 */
public final class StepUpRequiredException extends ApiException {

    private static final long serialVersionUID = 1L;

    /**
     * The structured signal: a response header present on (and ONLY on) a step-up refusal.
     * Byte-identical to admin-bff's constant of the same name and to mod-ui's
     * {@code STEP_UP_SIGNAL_HEADER}.
     */
    public static final String SIGNAL_HEADER = "X-Step-Up-Required";

    /**
     * The free-text phrase a client with no structured leg greps for. This constant is the
     * only place in main sources where the phrase is <b>emitted</b>: every gate message is
     * composed from it, so the pre-signal contract cannot be reworded away by editing one
     * controller. Enforced by {@code StepUpSignalContractTest}.
     */
    public static final String LEGACY_PHRASE = "requires step-up";

    /**
     * A flavour name is only ever a compile-time gate constant, so this is a tripwire for a
     * future programming error, not a runtime input filter. It also makes header-value
     * injection (CR/LF) structurally impossible: a bad value throws at construction and so
     * can never be written to the wire. Byte-identical to admin-bff's {@code SAFE_HEADER_NAME}
     * and to mod-ui's {@code SAFE_RETRY_HEADER} — a client that does not recognise the shape
     * ignores the signal and falls through to the phrase leg.
     */
    private static final Pattern SAFE_HEADER_NAME =
            Pattern.compile("^X-[A-Za-z0-9-]{1,60}-StepUp$");

    private final String retryHeader;

    private StepUpRequiredException(String retryHeader, String message) {
        super(HttpStatus.FORBIDDEN, withLegacyPhrase(message, retryHeader));
        if (retryHeader == null || !SAFE_HEADER_NAME.matcher(retryHeader).matches()) {
            throw new IllegalArgumentException(
                    "step-up retry header must be an X-<flavour>-StepUp gate constant, got: "
                            + retryHeader);
        }
        this.retryHeader = retryHeader;
    }

    /**
     * SOURCE-enforced old-client contract: this type is INCAPABLE of minting a refusal whose
     * message lacks {@link #LEGACY_PHRASE} — the constructor composes rather than trusting
     * callers. A message that already carries the phrase (case-insensitively, mirroring
     * mod-ui's {@code /requires step-up/i}) passes through VERBATIM. A null/blank message
     * becomes the canonical wording rather than NPE-ing the renderer's
     * {@code Map.of("error", ...)}.
     *
     * <p>Both fallback templates below are byte-identical to admin-bff's, including the
     * {@code present } before the header name — no caller in this repo can reach either
     * branch today ({@link #forRetryHeader} always composes a message that already carries
     * the phrase), but a divergence here would become a second dialect the day one does.
     */
    private static String withLegacyPhrase(String message, String retryHeader) {
        if (message != null && message.toLowerCase(Locale.ROOT).contains(LEGACY_PHRASE)) {
            return message;
        }
        if (message == null || message.isBlank()) {
            return "this operation " + LEGACY_PHRASE + " re-authentication (present "
                    + retryHeader + ")";
        }
        return message + " (" + LEGACY_PHRASE + " re-authentication: present " + retryHeader + ")";
    }

    /** The step-up flavour advertised on the wire; see the class javadoc for what it means here. */
    public String retryHeader() {
        return retryHeader;
    }

    /**
     * The canonical refusal: {@code "<verb> requires step-up re-authentication (present
     * <retryHeader>)"} — the same template admin-bff's gates emit, so one client sentence
     * covers both services.
     *
     * @param retryHeader a gate's {@code STEP_UP_HEADER} constant
     * @param verb        the operation as it reads in the message, e.g. {@code "banning a user"}
     */
    public static StepUpRequiredException forRetryHeader(String retryHeader, String verb) {
        return new StepUpRequiredException(retryHeader,
                verb + " " + LEGACY_PHRASE + " re-authentication (present " + retryHeader + ")");
    }
}
