package net.hugmesh.modbff.web;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import net.hugmesh.commons.web.ApiException;

import java.util.Map;

/**
 * Renders {@link ApiException} as the {@code {"error": message}} JSON body (and
 * the carried status) the mod-ui reads — matching the admin-bff reference shape
 * ({@code (await r.json().catch(()=>({}))).error || 'HTTP <status>'}), so the
 * shape must be {@code {error}} exactly. Works under WebFlux:
 * {@code @RestControllerAdvice} + {@code @ExceptionHandler} returning a
 * {@code ResponseEntity} is handled reactively (a controller's
 * {@code Mono.error(ApiException)} is routed here).
 *
 * <p><b>Step-up signal.</b> This is ALSO the single seam that stamps the structured step-up
 * signal: a {@link StepUpRequiredException} additionally carries the
 * {@value StepUpRequiredException#SIGNAL_HEADER} response header naming the step-up flavour
 * the caller must satisfy. The JSON body is left byte-identical — nothing is added to the
 * shared error body, so no unrelated error's wire shape moves — and the status stays whatever
 * the exception carries (403 for step-up; deliberately not 428, every existing client branches
 * on 403). Any OTHER {@link ApiException}, including an ordinary authz 403 such as the
 * privileged/self-target guard, is rendered exactly as before with NO signal header, which is
 * what keeps a routine DENY from popping an MFA prompt in the browser.
 *
 * <p>Note a denial raised by Spring Security itself (the {@code @PreAuthorize} role half, an
 * {@code AccessDeniedException}) never reaches this advice at all — it is rendered by the
 * security filter chain as a bare 403, so it too carries no signal. That asymmetry is the
 * point, and it is pinned by {@code ModStepUpGateControllerTest}.
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> handle(ApiException ex) {
        ResponseEntity.BodyBuilder response = ResponseEntity.status(ex.status());
        if (ex instanceof StepUpRequiredException stepUp) {
            response = response.header(StepUpRequiredException.SIGNAL_HEADER, stepUp.retryHeader());
        }
        return response.body(Map.of("error", ex.getMessage()));
    }
}
