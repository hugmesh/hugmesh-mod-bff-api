package net.hugmesh.modbff.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.server.ServerWebExchange;
import net.hugmesh.commons.security.DomainRegistry;

/**
 * Shared scaffolding for the wave-2 SECURITY-SLICE tests — builds a
 * {@link WebTestClient} that drives a real controller THROUGH the production
 * {@link SecurityConfig#filterChain} (the actual {@code authorizeExchange} path policy
 * + the OAuth2 resource-server wiring), with NO full Spring Boot context. MIRRORS the
 * {@code SecuritySliceSupport} pattern established in hugmesh-gateway PR #34 (and
 * replicated in this repo's in-flight PR #16); named {@code Wave2SecuritySliceSupport}
 * so it never collides with that PR's {@code config.SecuritySliceSupport} regardless of
 * merge order.
 *
 * <p>This is the load-bearing half of the copyable multi-issuer pattern: a
 * resource-server repo replicates the slice by (1) constructing its own
 * {@code SecurityConfig.filterChain} the same way here, (2) supplying issuer-specific
 * tokens via {@link net.hugmesh.modbff.testsupport.Wave2TestIssuer}, and (3)
 * asserting authority emission / domain resolution / 401 fail-closed against
 * {@code WebTestClient}.
 */
abstract class Wave2SecuritySliceSupport {

    /**
     * Build a {@link WebTestClient} bound to {@code controllers}, routed THROUGH the
     * real {@link SecurityConfig#filterChain} built from a fresh
     * {@link ServerHttpSecurity}. The chain is installed as a {@link WebFilterChainProxy}
     * web filter so the resource-server authentication + the {@code authorizeExchange}
     * policy run exactly as in production.
     *
     * @param registry        the issuer-&gt;domain registry (single- or multi-issuer)
     * @param tenantResolver  the OPTIONAL per-issuer resolver provider — pass
     *                        {@link #provider(Object)} with the real resolver to take
     *                        the multi-issuer swap, or {@link #absent()} to stay on
     *                        the single-issuer {@code o.jwt(...)} path
     * @param controllers     the @RestController instances under test
     */
    static WebTestClient sliceClient(
            DomainRegistry registry,
            ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>> tenantResolver,
            Object... controllers) {

        SecurityConfig config = new SecurityConfig(registry, tenantResolver, false, 600000L);
        // The chain now takes its accessDeniedHandler as an argument; build it exactly as the
        // @Bean method does, with the step-up gate on its SHIPPED-DARK default (false), so
        // these slices keep driving the production shape and the handler stays a pass-through.
        SecurityWebFilterChain chain = config.filterChain(ServerHttpSecurity.http(),
                config.modStepUpAccessDeniedHandler(config.modStepUpGate(false), config.roleHierarchy()));
        WebFilterChainProxy securityFilter = new WebFilterChainProxy(chain);

        return WebTestClient.bindToController(controllers)
                .webFilter(securityFilter)
                .build();
    }

    /** An {@link ObjectProvider} that yields the given value from
     *  {@code getIfAvailable()} (what {@code SecurityConfig} calls). */
    @SuppressWarnings("unchecked")
    static <T> ObjectProvider<T> provider(T value) {
        return new ObjectProvider<>() {
            @Override public T getObject() { return value; }
            @Override public T getObject(Object... args) { return value; }
            @Override public T getIfAvailable() { return value; }
            @Override public T getIfUnique() { return value; }
        };
    }

    /** An empty {@link ObjectProvider} ({@code getIfAvailable()} returns {@code null})
     *  — the single-issuer path, where no tenant resolver was contributed. */
    static <T> ObjectProvider<T> absent() {
        return new ObjectProvider<>() {
            @Override public T getObject() { throw new IllegalStateException("no value"); }
            @Override public T getObject(Object... args) { throw new IllegalStateException("no value"); }
            @Override public T getIfAvailable() { return null; }
            @Override public T getIfUnique() { return null; }
        };
    }
}
