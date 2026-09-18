package net.hugmesh.modbff.config;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authorization.ExceptionTranslationWebFilter;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.security.ModStepUpAccessDeniedHandler;
import net.hugmesh.modbff.security.ModStepUpGate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * STRUCTURAL pins for the step-up access-denied wiring — the two prose claims
 * {@link ModStepUpAccessDeniedHandler} and the README make that nothing else in the suite
 * could see, and that a 2026-09-17 review showed one of to have been FALSE as first written.
 *
 * <p><b>1. BOTH chains, not just the one the slices happen to run.</b>
 * {@link SecurityConfig} builds {@code devFilterChain} ({@code @Profile({"dev","test"})})
 * and {@code filterChain} ({@code @Profile("!dev & !test")}), and installs the handler on
 * both "so the two cannot drift". Every {@code @WebFluxTest} slice in this repo runs with no
 * profile active and therefore only exercises the PROD chain — deleting the dev chain's
 * {@code .exceptionHandling(...)} left the whole suite green (measured).
 * {@link net.hugmesh.modbff.ModStepUpSignalDevChainTest} closes that behaviourally; this
 * closes it structurally, one assertion per chain, with no profile machinery involved.
 *
 * <p><b>2. "Every other refusal stays byte-identical" — now actually true, and measured.</b>
 * Installing an explicit {@code accessDeniedHandler} makes {@code ServerHttpSecurity}
 * discard its {@code defaultAccessDeniedHandlers} wholesale. For a chain that configures
 * {@code oauth2ResourceServer} — both of ours do — those defaults resolve to
 * {@code BearerTokenServerAccessDeniedHandler}, not to the bare status handler, so a
 * pass-through that delegated to {@code HttpStatusServerAccessDeniedHandler} would have
 * silently dropped {@code WWW-Authenticate: Bearer} from, and added a {@code text/plain}
 * {@code "Access Denied"} body to, EVERY non-step-up 403 this service emits. The delegate is
 * now extracted from a stock chain at RUNTIME and compared field by field, so the day
 * Spring resolves its defaults differently this goes red instead of the wire moving under a
 * green suite.
 */
class StepUpAccessDeniedWiringTest {

    /**
     * Two trusted issuers so {@code DomainRegistry.isMultiIssuer()} holds and
     * {@code configureResourceServer} takes the per-issuer resolver branch. That is
     * deliberate PLUMBING, not the subject: {@code exceptionHandling} is configured on the
     * chain BEFORE {@code oauth2ResourceServer} in both {@code @Bean} methods, so the
     * access-denied wiring is the same either way — but the single-issuer {@code o.jwt(...)}
     * branch resolves its {@code ReactiveJwtDecoder} from the ApplicationContext, and these
     * chains are built from a bare {@code ServerHttpSecurity.http()} with no context at all.
     */
    private static final String ISSUERS_CSV =
            "http://127.0.0.1:1=brandx,http://127.0.0.1:2=brandy";

    /** Never invoked: no request is driven through a chain here, only handlers. */
    private static final ReactiveAuthenticationManagerResolver<ServerWebExchange> RESOLVER =
            exchange -> Mono.empty();

    private static SecurityConfig config() {
        return new SecurityConfig(new DomainRegistry("http://127.0.0.1:1", ISSUERS_CSV),
                SecuritySliceSupport.provider(RESOLVER), false, 600000L);
    }

    /** The {@code accessDeniedHandler} the built chain will actually dispatch a 403 through. */
    private static ServerAccessDeniedHandler accessDeniedHandlerOf(SecurityWebFilterChain chain) {
        List<WebFilter> filters = chain.getWebFilters().collectList().block();
        assertThat(filters).as("built chain filters").isNotNull().isNotEmpty();
        ExceptionTranslationWebFilter translation = filters.stream()
                .filter(ExceptionTranslationWebFilter.class::isInstance)
                .map(ExceptionTranslationWebFilter.class::cast)
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "no ExceptionTranslationWebFilter in the chain — a 403 cannot reach any "
                                + "accessDeniedHandler at all"));
        return (ServerAccessDeniedHandler)
                ReflectionTestUtils.getField(translation, "accessDeniedHandler");
    }

    /**
     * The handler Spring Security itself installs for a chain shaped like ours MINUS the
     * {@code exceptionHandling} call — i.e. exactly what {@code origin/main} dispatched every
     * denial through. Resolved at runtime rather than named, so an upstream change in how the
     * defaults are chosen is picked up here instead of being assumed away.
     */
    private static ServerAccessDeniedHandler springsOwnHandlerForThisChainShape() {
        return accessDeniedHandlerOf(ServerHttpSecurity.http()
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(ex -> ex.anyExchange().authenticated())
                .oauth2ResourceServer(o -> o.authenticationManagerResolver(RESOLVER))
                .build());
    }

    @Test
    void bothProfileChains_dispatchTheirDenialsThroughTheStepUpHandler() {
        SecurityConfig config = config();
        ModStepUpAccessDeniedHandler handler = config.modStepUpAccessDeniedHandler(
                config.modStepUpGate(false), config.roleHierarchy());

        assertThat(accessDeniedHandlerOf(config.devFilterChain(ServerHttpSecurity.http(), handler)))
                .as("devFilterChain (@Profile dev,test) accessDeniedHandler")
                .isSameAs(handler);
        assertThat(accessDeniedHandlerOf(config.filterChain(ServerHttpSecurity.http(), handler)))
                .as("filterChain (@Profile !dev & !test) accessDeniedHandler")
                .isSameAs(handler);
    }

    /**
     * THE EQUIVALENCE. Drive the same {@link AccessDeniedException} through Spring's own
     * handler and through ours (gate DARK, so the pass-through branch) and compare the whole
     * response: status, every header, and the body. This is the assertion that would have
     * caught the dropped {@code WWW-Authenticate: Bearer} and the invented
     * {@code "Access Denied"} body.
     */
    @Test
    void nonStepUpDenial_isByteIdenticalToWhatSpringWouldHaveSent() {
        SecurityConfig config = config();
        ModStepUpAccessDeniedHandler ours = config.modStepUpAccessDeniedHandler(
                config.modStepUpGate(false), config.roleHierarchy());
        assertResponsesMatch(springsOwnHandlerForThisChainShape(), ours, "/bff/mod/audit");
    }

    /**
     * The same equivalence with the gate ARMED, on a path that is NOT one of the five gated
     * shapes — the other half of the pass-through: arming the flag must not move the wire for
     * anything outside {@link ModStepUpGate#SENSITIVE_WRITES}.
     */
    @Test
    void armedGate_stillPassesThroughUnchanged_onANonSensitivePath() {
        SecurityConfig config = config();
        ModStepUpAccessDeniedHandler ours = config.modStepUpAccessDeniedHandler(
                config.modStepUpGate(true), config.roleHierarchy());
        assertResponsesMatch(springsOwnHandlerForThisChainShape(), ours, "/bff/mod/moderation");
    }

    /** Run both handlers over an identical request and compare the responses in full. */
    private static void assertResponsesMatch(ServerAccessDeniedHandler reference,
                                             ServerAccessDeniedHandler actual,
                                             String path) {
        AccessDeniedException denied = new AccessDeniedException("Access Denied");
        MockServerWebExchange expected = MockServerWebExchange.from(MockServerHttpRequest.get(path));
        MockServerWebExchange got = MockServerWebExchange.from(MockServerHttpRequest.get(path));
        reference.handle(expected, denied).block();
        actual.handle(got, denied).block();

        HttpStatusCode expectedStatus = expected.getResponse().getStatusCode();
        assertThat(expectedStatus).as("reference handler must actually have refused").isNotNull();
        assertThat(got.getResponse().getStatusCode())
                .as("status of a non-step-up denial on %s", path).isEqualTo(expectedStatus);
        assertThat(headersOf(got)).as("headers of a non-step-up denial on %s", path)
                .isEqualTo(headersOf(expected));
        assertThat(bodyOf(got)).as("body of a non-step-up denial on %s", path)
                .isEqualTo(bodyOf(expected));
    }

    private static HttpHeaders headersOf(MockServerWebExchange exchange) {
        return exchange.getResponse().getHeaders();
    }

    private static String bodyOf(MockServerWebExchange exchange) {
        String body = exchange.getResponse().getBodyAsString()
                .defaultIfEmpty("")
                .block();
        return body == null ? "" : new String(body.getBytes(StandardCharsets.UTF_8),
                StandardCharsets.UTF_8);
    }
}
