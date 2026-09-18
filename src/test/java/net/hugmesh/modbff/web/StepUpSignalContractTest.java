package net.hugmesh.modbff.web;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.modbff.security.ModStepUpGate;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The step-up WIRE CONTRACT, asserted at the type that mints it and the advice that renders
 * it — the two halves hugmesh-mod-ui reads. See hugmesh-mod-bff-api#16.
 */
class StepUpSignalContractTest {

    // ── the minted refusal ─────────────────────────────────────────────────────

    @Test
    void theRefusalIs403_carriesTheFlavour_andKeepsTheLegacyPhrase() {
        StepUpRequiredException ex = ModStepUpGate.denial("banning a user");

        assertThat(ex.status()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(ex.retryHeader()).isEqualTo(ModStepUpGate.STEP_UP_HEADER);
        assertThat(ex.getMessage()).contains(StepUpRequiredException.LEGACY_PHRASE);
        assertThat(ex.getMessage()).startsWith("banning a user");
        assertThat(ex).isInstanceOf(ApiException.class);
    }

    /** 428 is the "conventional" step-up status and mod-ui accepts it, but nothing on this
     *  platform emits it: every client branches on 403 and a status move would be a breaking,
     *  non-rolling-deployable change. Pinned so a later "make it a 428" is a decision. */
    @Test
    void theStatusIsDeliberatelyNot428() {
        assertThat(ModStepUpGate.denial("blocking a user").status())
                .isNotEqualTo(HttpStatus.PRECONDITION_REQUIRED);
    }

    /** {@code ModController} spells the signal header as a literal in its {@code @ApiResponse}
     *  documentation (an annotation attribute needs a compile-time constant). Pin the two
     *  together so the published OpenAPI contract cannot document a header the service does
     *  not send. */
    @Test
    void theDocumentedHeaderName_isTheOneTheServiceSends() {
        assertThat(net.hugmesh.modbff.ModController.STEP_UP_SIGNAL_HEADER)
                .isEqualTo(StepUpRequiredException.SIGNAL_HEADER);
    }

    /**
     * The flavour is written to a response header, so a value carrying CR/LF would be a
     * header-injection vector. It is structurally impossible: a bad value throws at
     * construction and can never reach the wire.
     */
    @Test
    void aFlavourThatIsNotAGateConstant_isRefusedAtConstruction() {
        assertThatThrownBy(() -> StepUpRequiredException.forRetryHeader(
                        "X-Mod-StepUp\r\nX-Injected: yes", "banning a user"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> StepUpRequiredException.forRetryHeader("Authorization", "x"))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> StepUpRequiredException.forRetryHeader(null, "x"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    /** Every verb in the gate's inventory produces a message an old phrase-sniffing client
     *  still recognises — the constructor composes the phrase rather than trusting callers. */
    @Test
    void everyDeclaredVerb_producesAPhraseSniffableMessage() {
        for (ModStepUpGate.SensitiveWrite w : ModStepUpGate.SENSITIVE_WRITES) {
            assertThat(ModStepUpGate.denial(w.verb()).getMessage())
                    .containsIgnoringCase(StepUpRequiredException.LEGACY_PHRASE);
        }
    }

    // ── the rendered response ──────────────────────────────────────────────────

    @Test
    void theAdviceStampsTheSignalOnAStepUpRefusal_andLeavesTheBodyShapeAlone() {
        ResponseEntity<Map<String, Object>> response =
                new ApiExceptionHandler().handle(ModStepUpGate.denial("banning a user"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getHeaders().getFirst(StepUpRequiredException.SIGNAL_HEADER))
                .isEqualTo(ModStepUpGate.STEP_UP_HEADER);
        assertThat(response.getBody()).containsOnlyKeys("error");
        assertThat(String.valueOf(response.getBody().get("error")))
                .contains(StepUpRequiredException.LEGACY_PHRASE);
    }

    /** An ORDINARY 403 — the privileged/self-target guard, say — must stay bare, or every
     *  routine refusal pops an MFA dialog. */
    @Test
    void theAdviceLeavesAnOrdinaryApiExceptionUnsignalled() {
        ResponseEntity<Map<String, Object>> response = new ApiExceptionHandler()
                .handle(ApiException.forbidden("cannot ban a moderator"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getHeaders().containsHeader(StepUpRequiredException.SIGNAL_HEADER))
                .isFalse();
        assertThat(response.getBody()).isEqualTo(Map.of("error", "cannot ban a moderator"));
    }
}
