package net.hugmesh.modbff;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;

/**
 * Regression guard for the resilience4j circuit-breaker wiring that the
 * Spring Boot 3-&gt;4 migration silently broke fleet-wide.
 *
 * <p>This service applies {@code @CircuitBreaker} via a Spring AOP
 * {@code @Aspect} ({@code io.github.resilience4j.spring6.circuitbreaker
 * .configure.CircuitBreakerAspect}), which resilience4j registers only
 * under its {@code AspectJOnClasspathCondition} (it checks for
 * {@code org.aspectj.lang.ProceedingJoinPoint}); Boot's
 * {@code AopAutoConfiguration} likewise enables AspectJ auto-proxy only
 * when AspectJ is on the classpath. {@code resilience4j-spring-boot4}
 * does NOT pull it transitively, and Boot 4 removed the old
 * {@code spring-boot-starter-aop} convenience starter — so if the
 * explicit {@code org.aspectj:aspectjweaver} dependency is ever dropped,
 * EVERY {@code @CircuitBreaker} (incl. the fail-closed/fail-open
 * fallbacks) silently becomes a no-op while the build stays green.
 *
 * <p>This test fails fast in exactly that case.
 */
class CircuitBreakerWiringTest {

    /**
     * The exact class resilience4j's {@code AspectJOnClasspathCondition}
     * checks for; present iff {@code aspectjweaver} is on the classpath.
     */
    private static final String ASPECTJ_MARKER =
            "org.aspectj.lang.ProceedingJoinPoint";

    @Test
    void aspectJOnClasspath_soResilience4jCircuitBreakerActuallyWires() {
        assertThatCode(() -> Class.forName(ASPECTJ_MARKER))
                .as("aspectjweaver MUST be on the classpath, or resilience4j "
                        + "never registers the CircuitBreakerAspect and every "
                        + "@CircuitBreaker is a silent no-op under Spring Boot 4")
                .doesNotThrowAnyException();
    }
}
