package net.hugmesh.modbff.web;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.bind.support.WebExchangeBindException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reactive validation advice: turns a jakarta/Spring validation failure into a
 * clean {@code 400 Bad Request} with a structured field-error body, instead of the
 * framework default (a malformed {@code @Valid @RequestBody} would otherwise surface
 * as an opaque error). Two sources are mapped:
 *
 * <ul>
 *   <li>{@link WebExchangeBindException} — a {@code @Valid @RequestBody} DTO whose
 *       jakarta constraints failed (one entry per invalid field).</li>
 *   <li>{@link ConstraintViolationException} — a {@code @Validated} controller's
 *       {@code @PathVariable}/{@code @RequestParam} constraint failure (e.g. the
 *       {@code status} query param charset/length guard on {@code /bff/mod/moderation}).</li>
 * </ul>
 *
 * <p>The body shape is {@code {"error":"validation failed","fields":{field:msg}}}.
 * The {@code error} key matches the {@code {error}} convention the mod-ui reads
 * (see {@link ApiExceptionHandler}); {@code fields} is additive. This advice handles
 * disjoint exception types from {@link ApiExceptionHandler}, so the two coexist.
 */
@RestControllerAdvice
public class ValidationExceptionHandler {

    @ExceptionHandler(WebExchangeBindException.class)
    public ResponseEntity<Map<String, Object>> handleBind(WebExchangeBindException ex) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (FieldError fe : ex.getFieldErrors()) {
            fields.putIfAbsent(fe.getField(),
                    fe.getDefaultMessage() == null ? "invalid" : fe.getDefaultMessage());
        }
        return badRequest(fields);
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<Map<String, Object>> handleConstraint(ConstraintViolationException ex) {
        Map<String, String> fields = new LinkedHashMap<>();
        for (ConstraintViolation<?> v : ex.getConstraintViolations()) {
            String path = v.getPropertyPath() == null ? "" : v.getPropertyPath().toString();
            String leaf = path.contains(".") ? path.substring(path.lastIndexOf('.') + 1) : path;
            fields.putIfAbsent(leaf, v.getMessage());
        }
        return badRequest(fields);
    }

    private static ResponseEntity<Map<String, Object>> badRequest(Map<String, String> fields) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "validation failed");
        body.put("fields", fields);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }
}
