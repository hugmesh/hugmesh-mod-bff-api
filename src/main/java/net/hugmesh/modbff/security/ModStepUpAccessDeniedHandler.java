package net.hugmesh.modbff.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.server.authorization.HttpStatusServerAccessDeniedHandler;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;
import reactor.core.publisher.Mono;

import net.hugmesh.modbff.web.StepUpRequiredException;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Makes a STEP-UP refusal recognisable on the wire, and changes nothing else.
 *
 * <h2>The problem</h2>
 * {@link ModStepUpGate} denies through a {@code @PreAuthorize} conjunct
 * ({@code "hasAnyRole('MOD','ADMIN') and @modStepUpGate.satisfied(authentication)"}), so the
 * refusal it produces is an ordinary {@link AccessDeniedException}: Spring Security's default
 * {@link HttpStatusServerAccessDeniedHandler} renders a bare 403 with no body and no header,
 * byte-identical to "you may not ban a moderator". hugmesh-mod-ui shipped the whole client
 * half of the step-up flow and it is INERT because neither of its detection legs can fire
 * against that denial. See hugmesh-mod-bff-api#16.
 *
 * <h2>What this handler does</h2>
 * It is installed as the chain's {@code accessDeniedHandler} and, for the narrow case below,
 * renders the refusal as {@link StepUpRequiredException} does — status 403 (unchanged),
 * {@code {"error": "<verb> requires step-up re-authentication (present X-Mod-StepUp)"}} and
 * the {@value StepUpRequiredException#SIGNAL_HEADER} response header. EVERY other denial is
 * delegated, untouched, to the same {@link HttpStatusServerAccessDeniedHandler} Spring
 * Security would have used — so no other refusal's wire shape moves.
 *
 * <h2>The narrow case — all four must hold</h2>
 * <ol>
 *   <li>the gate is ARMED ({@code app.mfa.enforce-sensitive-writes=true}); while it ships
 *       dark the predicate returns true unconditionally, so a denial CANNOT have come from
 *       the step-up leg and this handler is a pure pass-through;</li>
 *   <li>the request matches one of {@link ModStepUpGate#SENSITIVE_WRITES} — the five shapes
 *       that actually carry the conjunct;</li>
 *   <li>the caller passes the ROLE half ({@code hasAnyRole('MOD','ADMIN')}, evaluated through
 *       the same {@link RoleHierarchy} the method-security expression handler uses, so
 *       {@code ROLE_SUPERADMIN} counts). <b>This is the condition that matters.</b> The
 *       chain-level {@code /bff/mod/**} rule denies a plain {@code ROLE_USER} on exactly
 *       these paths, and that refusal arrives here too — without this check it would be
 *       dressed up as a step-up requirement and mod-ui would offer an MFA challenge that
 *       cannot possibly let them through;</li>
 *   <li>the caller does NOT satisfy the gate ({@code !gate.satisfied(auth)}) — i.e. the
 *       step-up conjunct is the leg that said no.</li>
 * </ol>
 * Conditions 3 and 4 are re-evaluated rather than remembered because an
 * {@link AccessDeniedException} carries no record of which conjunct failed. Both are pure
 * functions of the {@link Authentication} that was already decided against, so re-asking them
 * cannot reach a different answer than the gate did; neither can GRANT anything, because the
 * request is already denied and this handler only ever writes a 403.
 *
 * @see ModStepUpGate
 * @see StepUpRequiredException
 */
public class ModStepUpAccessDeniedHandler implements ServerAccessDeniedHandler {

    /** Exactly what {@code ServerHttpSecurity} installs when nothing overrides it. */
    private static final ServerAccessDeniedHandler DEFAULT =
            new HttpStatusServerAccessDeniedHandler(HttpStatus.FORBIDDEN);

    private static final ObjectMapper JSON = new ObjectMapper();

    private final ModStepUpGate gate;
    private final RoleHierarchy roleHierarchy;
    private final List<CompiledWrite> sensitive;

    public ModStepUpAccessDeniedHandler(ModStepUpGate gate, RoleHierarchy roleHierarchy) {
        this.gate = gate;
        this.roleHierarchy = roleHierarchy;
        PathPatternParser parser = new PathPatternParser();
        List<CompiledWrite> compiled = new ArrayList<>();
        for (ModStepUpGate.SensitiveWrite w : ModStepUpGate.SENSITIVE_WRITES) {
            List<PathPattern> patterns = new ArrayList<>();
            for (String p : w.pathPatterns()) {
                patterns.add(parser.parse(p));
            }
            compiled.add(new CompiledWrite(w, List.copyOf(patterns)));
        }
        this.sensitive = List.copyOf(compiled);
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
        ModStepUpGate.SensitiveWrite hit = gate.isEnforced() ? match(exchange) : null;
        if (hit == null) {
            return DEFAULT.handle(exchange, denied);
        }
        return ReactiveSecurityContextHolder.getContext()
                .flatMap(ctx -> Mono.justOrEmpty(ctx.getAuthentication()))
                .map(this::stepUpWasTheFailingLeg)
                .defaultIfEmpty(Boolean.FALSE)
                // NOTE: a Mono<Void> completes EMPTY, so switchIfEmpty() after the write would
                // run the default handler as well and commit the response twice. Branching on
                // a Boolean keeps exactly one writer.
                .flatMap(isStepUp -> Boolean.TRUE.equals(isStepUp)
                        ? writeStepUpRefusal(exchange, hit)
                        : DEFAULT.handle(exchange, denied));
    }

    /** The {@link SecurityContext}-derived half of the narrow case: conditions 3 and 4. */
    private boolean stepUpWasTheFailingLeg(Authentication auth) {
        return roleHalfSatisfied(auth) && !gate.satisfied(auth);
    }

    /** {@code hasAnyRole('MOD','ADMIN')} with the role hierarchy applied — the same question
     *  the {@code @PreAuthorize} role conjunct asked. */
    private boolean roleHalfSatisfied(Authentication auth) {
        if (auth == null || !auth.isAuthenticated()) {
            return false;
        }
        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        if (authorities == null) {
            return false;
        }
        Collection<? extends GrantedAuthority> reachable = roleHierarchy == null
                ? authorities
                : roleHierarchy.getReachableGrantedAuthorities(authorities);
        for (GrantedAuthority a : reachable) {
            String name = a.getAuthority();
            if ("ROLE_MOD".equals(name) || "ROLE_ADMIN".equals(name)) {
                return true;
            }
        }
        return false;
    }

    /** The request shape this denial was for, or {@code null} when it is not a gated one. */
    private ModStepUpGate.SensitiveWrite match(ServerWebExchange exchange) {
        var request = exchange.getRequest();
        var path = request.getPath().pathWithinApplication();
        for (CompiledWrite w : sensitive) {
            if (!w.write().method().equals(request.getMethod())) {
                continue;
            }
            for (PathPattern pattern : w.patterns()) {
                if (pattern.matches(path)) {
                    return w.write();
                }
            }
        }
        return null;
    }

    /**
     * Render the refusal. The status, body shape and header are taken FROM the exception so
     * this handler and {@link net.hugmesh.modbff.web.ApiExceptionHandler} cannot disagree —
     * {@link ModStepUpGate#denial(String)} is the one place either of them mints.
     */
    private Mono<Void> writeStepUpRefusal(ServerWebExchange exchange,
                                          ModStepUpGate.SensitiveWrite write) {
        StepUpRequiredException refusal = ModStepUpGate.denial(write.verb());
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(refusal.status());
        response.getHeaders().set(StepUpRequiredException.SIGNAL_HEADER, refusal.retryHeader());
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        byte[] body = errorBody(refusal.getMessage());
        DataBuffer buffer = response.bufferFactory().wrap(body);
        return response.writeWith(Mono.just(buffer));
    }

    /** {@code {"error": "<message>"}} — the shape {@code ApiExceptionHandler} emits, built
     *  through Jackson so no message can produce malformed JSON. */
    private static byte[] errorBody(String message) {
        try {
            return JSON.writeValueAsBytes(Map.of("error", message));
        } catch (JsonProcessingException e) {
            // Unreachable for a Map<String,String>; fall back to the literal rather than
            // failing the response, since the caller is already being refused.
            return "{\"error\":\"requires step-up re-authentication\"}"
                    .getBytes(StandardCharsets.UTF_8);
        }
    }

    /** A {@link ModStepUpGate.SensitiveWrite} with its path templates parsed once. */
    private record CompiledWrite(ModStepUpGate.SensitiveWrite write, List<PathPattern> patterns) {}
}
