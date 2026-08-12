package net.hugmesh.modbff.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.DomainRegistry;

/**
 * Registers the shared {@code net.hugmesh.commons} security/tenancy beans into
 * this consumer's application context.
 *
 * <p><b>Why this exists (recipe note for the commons fan-out).</b> When
 * {@link DomainRegistry} (an {@code @Component}) and {@link TenancyResourceServerConfig}
 * (an {@code @Configuration} gated by {@code @ConditionalOnExpression}) lived inside
 * this repo's own {@code net.hugmesh.modbff.config} / {@code .security}
 * packages, the {@code @SpringBootApplication} component scan over
 * {@code net.hugmesh.modbff} picked them up automatically. After the lift they
 * live under {@code net.hugmesh.commons.*}, which the mod-BFF scan does NOT
 * cover, so {@code SecurityConfig}'s {@code DomainRegistry} dependency went unsatisfied
 * and every {@code @SpringBootTest} failed to load its context.
 *
 * <p>Rather than widen the application's {@code scanBasePackages} to the whole commons
 * tree (which would auto-adopt every future commons {@code @Component} implicitly), we
 * {@code @Import} exactly the two commons beans this BFF needs:
 * <ul>
 *   <li>{@link DomainRegistry} — the issuer-&gt;domain registry consumed by
 *       {@code SecurityConfig}, the controllers/service and the converter. Its
 *       {@code @Value} constructor wiring
 *       ({@code spring.security.oauth2.resourceserver.jwt.issuer-uri} +
 *       {@code app.tenancy.issuers}) is honoured by {@code @Import} exactly as a
 *       component scan would.</li>
 *   <li>{@link TenancyResourceServerConfig} — the CONFIG-GATED multi-issuer wiring.
 *       Importing the {@code @Configuration} class PRESERVES its
 *       {@code @ConditionalOnExpression("'${app.tenancy.issuers:}'.contains('=')")}
 *       guard, so single-issuer clusters stay byte-for-byte on the existing
 *       single-issuer path and the {@code tenantAuthManagerResolver} {@code @Bean} is
 *       contributed ONLY when real {@code issuer=domain} pairs are configured —
 *       identical behaviour to the pre-lift in-repo {@code @Configuration}.</li>
 * </ul>
 *
 * <p>Every consumer of hugmesh-commons drops in this same tiny {@code @Import}
 * configuration (adjusting only its package) — it is the canonical wiring step of the
 * adoption recipe.
 */
@Configuration
@Import({DomainRegistry.class, TenancyResourceServerConfig.class})
public class CommonsSecurityConfig {
}
