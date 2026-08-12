package net.hugmesh.commons.config;

import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.web.server.ServerWebExchange;

/**
 * Same-package TEST accessor for the package-private
 * {@link TenancyResourceServerConfig#tenantAuthManagerResolver()} {@code @Bean}.
 *
 * <p>WHY THIS EXISTS (recipe note for the commons fan-out). When the multi-issuer
 * wiring lived <em>inside</em> this repo's {@code config} package, its SECURITY-SLICE
 * tests could call the package-private {@code @Bean} method directly to build a
 * {@link ReactiveAuthenticationManagerResolver} and feed it to the sliced
 * {@code SecurityConfig} WITHOUT a full Spring context. After the lift,
 * {@code TenancyResourceServerConfig} lives in {@code net.hugmesh.commons.config}
 * and that bean method stays <b>package-private by design</b> (only Spring should
 * publish it). A slice test in the consumer's own package therefore can no longer
 * reach it.
 *
 * <p>This tiny accessor — placed in {@code net.hugmesh.commons.config} under
 * the CONSUMER's <b>test</b> sources — re-opens exactly that one method to the slice
 * tests, with no change to the shipped commons jar and no widening of the production
 * API surface. Every consumer that runs the multi-issuer security slice drops this
 * same 1-method file into its {@code src/test/java/net/hugmesh/commons/config/}.
 */
public final class TenancyResolvers {

    private TenancyResolvers() {}

    /** Build the multi-issuer tenant {@link ReactiveAuthenticationManagerResolver}
     *  from a configured {@link TenancyResourceServerConfig} — the exact resolver the
     *  production {@code @Bean} publishes, for use in a security slice without a
     *  Spring context. */
    public static ReactiveAuthenticationManagerResolver<ServerWebExchange> tenantResolver(
            TenancyResourceServerConfig config) {
        return config.tenantAuthManagerResolver();
    }
}
