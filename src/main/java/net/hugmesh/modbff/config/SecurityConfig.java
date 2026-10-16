package net.hugmesh.modbff.config;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.core.GrantedAuthorityDefaults;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.security.CasdoorAuthorities;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.auth.BffCookieAuthenticationWebFilter;
import net.hugmesh.modbff.security.ModStepUpAccessDeniedHandler;
import net.hugmesh.modbff.security.ModStepUpGate;

/**
 * Casdoor-aware OAuth2 resource-server security for the moderator BFF (reactive
 * WebFlux). {@code @EnableReactiveMethodSecurity} activates the
 * {@code @PreAuthorize("hasAnyRole('MOD','ADMIN')")} gates on the mod endpoints. The
 * JWT→authority mapping delegates to the shared {@link CasdoorAuthorities} converter
 * (COPIED VERBATIM from hugmesh-gateway): Casdoor's {@code roles} claim (string or
 * {name} objects) -&gt; {@code ROLE_<UPPER>}, {@code permissions} verbatim EXCEPT the
 * reserved {@code ROLE_}/{@code DOMAIN_} prefixes (authority-injection defense), legacy
 * {@code isAdmin} -&gt; {@code ROLE_ADMIN}, a {@code ROLE_USER} floor, plus exactly one
 * issuer-derived {@code DOMAIN_<x>} authority (the per-brand tenant scope).
 *
 * <p>Mod floor: the whole {@code /bff/mod/**} surface is gated to
 * {@code hasAnyRole('MOD','ADMIN','SUPERADMIN')} at the chain (SUPERADMIN is the
 * cross-domain infra control plane), with {@code @PreAuthorize} re-checking at each
 * method (defence in depth). There is NO pre-auth {@code /login} / {@code /register}
 * plumbing here — registration is owned by admin-bff; this BFF is post-login, JWT-only.
 *
 * <p><b>Multi-issuer (per-brand Casdoor) is OPT-IN + backward-compatible.</b> A
 * single-issuer cluster keeps the EXISTING single {@code o.jwt(...)} issuer-uri decoder
 * path verbatim. Only when {@link TenancyResourceServerConfig} contributes a per-issuer
 * resolver AND {@link DomainRegistry#isMultiIssuer()} does the chain swap to the
 * per-issuer authentication-manager resolver (each trusted brand Casdoor validates its
 * own tokens; an unknown {@code iss} 401s, fail-closed).
 */
@Configuration
@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
public class SecurityConfig {

    /**
     * SpringDoc OpenAPI spec + Swagger UI surface. Public under dev/test so
     * {@code gen:fetch} can curl the spec without a token; ROLE_ADMIN (or SUPERADMIN)
     * everywhere else (prod) so the API contract is never publicly reachable.
     */
    private static final String[] SPEC_PATHS = {
            "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/webjars/swagger-ui/**"
    };

    private final DomainRegistry domainRegistry;

    /** OPTIONAL per-brand multi-issuer resolver, contributed by
     *  {@link TenancyResourceServerConfig} ONLY when {@code app.tenancy.issuers}
     *  genuinely carries issuer=domain pairs. Absent on a single-issuer cluster. */
    private final ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
            tenantAuthManagerResolver;

    /** D8 MFA floor (fan-out from the gateway). Ships DARK — {@code app.mfa.enabled}
     *  defaults {@code false}, so the converter emits the byte-identical legacy
     *  authority set and {@code MFA_SATISFIED} is never produced. {@code app.mfa
     *  .freshness-window} is the {@code 0 <= now - ts <= window} window (default 10m).
     *  BOTH the single-issuer path here and the multi-issuer path
     *  ({@link TenancyResourceServerConfig}) must build the SAME {@link CasdoorAuthorities.MfaConfig}
     *  so they derive identically. */
    private final boolean mfaEnabled;
    private final long mfaFreshnessWindowMillis;

    public SecurityConfig(DomainRegistry domainRegistry,
                          ObjectProvider<ReactiveAuthenticationManagerResolver<ServerWebExchange>>
                                  tenantAuthManagerResolver,
                          @Value("${app.mfa.enabled:false}") boolean mfaEnabled,
                          @Value("${app.mfa.freshness-window:600000}") long mfaFreshnessWindowMillis) {
        this.domainRegistry = domainRegistry;
        this.tenantAuthManagerResolver = tenantAuthManagerResolver;
        this.mfaEnabled = mfaEnabled;
        this.mfaFreshnessWindowMillis = mfaFreshnessWindowMillis;
    }

    /**
     * Shared route rules common to BOTH the dev/test and prod filter chains. The ONLY
     * difference between the two profiles is how {@link #SPEC_PATHS} is gated, so every
     * other route lives here to keep the two chains in lockstep.
     */
    private static void commonRoutes(ServerHttpSecurity.AuthorizeExchangeSpec ex) {
        // Probes are public so k8s/Docker healthchecks need no token.
        ex.pathMatchers("/actuator/health", "/actuator/health/**", "/actuator/info").permitAll();
        // EVERY other actuator path is an operator surface (env, beans, heapdump, metrics,
        // loggers, prometheus ...). Today the exposure list (health,info) leaves nothing
        // behind it, but an env override or a new starter widens that list with no code
        // change, and the anyExchange().authenticated() floor below would then hand it to
        // any logged-in ROLE_USER. Decide it here, first-match-wins, so it fails CLOSED
        // whatever is exposed. Explicit hasAnyRole, not the hierarchy edge.
        ex.pathMatchers("/actuator/**").hasAnyRole("ADMIN", "SUPERADMIN");
        // Moderator surface — defence-in-depth on top of the gateway's route-access
        // rules + the @PreAuthorize method gates. A MOD or an ADMIN, from the Casdoor
        // JWT, PLUS the cross-domain SUPERADMIN infra role (which reaches every brand's
        // surface). NO infra/server-admin paths live under here.
        ex.pathMatchers("/bff/mod/**").hasAnyRole("MOD", "ADMIN", "SUPERADMIN");
    }

    /**
     * Hardened HTTP response headers for a pure-JSON resource server (the BFF
     * defensive-minimum from the org security plan: OWASP A05 / ASVS V14.4 /
     * NIST 800-228). This BFF NEVER serves an HTML document and always sits BEHIND the
     * TLS-terminating gateway front door, so:
     *
     * <ul>
     *   <li>ADDS a no-content {@code Content-Security-Policy: default-src 'none';
     *       frame-ancestors 'none'} as defense-in-depth (a JSON body has no script/style
     *       to load and must never be framed);</li>
     *   <li>KEEPS Spring Security's reactive secure DEFAULTS untouched —
     *       {@code X-Content-Type-Options: nosniff}, {@code X-Frame-Options: DENY},
     *       {@code Cache-Control: no-store}, {@code Referrer-Policy} — i.e. nosniff /
     *       frame-options are NOT disabled;</li>
     *   <li>OMITS HSTS (meaningless / misleading over a plaintext intra-mesh hop — it
     *       lives ONLY at the gateway's TLS edge) and OMITS Permissions-Policy (no
     *       document to govern).</li>
     * </ul>
     *
     * <p>This is purely ADDITIVE — it changes no authz rule, no issuer validation and
     * does not touch the {@code csrf.disable()} posture (correct-by-design for a
     * stateless bearer resource server).
     */
    private static void hardenedHeaders(ServerHttpSecurity.HeaderSpec h) {
        h.contentSecurityPolicy(csp ->
                csp.policyDirectives("default-src 'none'; frame-ancestors 'none'"));
        // nosniff + Cache-Control + X-Frame-Options DENY + Referrer-Policy remain Spring
        // Security reactive secure defaults — intentionally left implicit (NOT disabled).
    }

    /**
     * Dev / test profile: the OpenAPI spec + Swagger UI are PUBLIC so {@code gen:fetch}
     * (ng-openapi-gen) and the docs pipeline can curl {@code /v3/api-docs} locally
     * without a Casdoor token. Every non-spec route is identical to prod.
     */
    @Bean
    @Profile({"dev", "test"})
    SecurityWebFilterChain devFilterChain(final ServerHttpSecurity http,
                                          final ModStepUpAccessDeniedHandler stepUpAccessDenied) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .headers(SecurityConfig::hardenedHeaders)
                .exceptionHandling(e -> e.accessDeniedHandler(stepUpAccessDenied))
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).permitAll();
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(this::configureResourceServer)
                .build();
    }

    /**
     * Production profile (default — active whenever neither {@code dev} nor
     * {@code test} is): the OpenAPI spec + Swagger UI require ROLE_ADMIN (or the
     * cross-domain SUPERADMIN) so the API contract is never publicly reachable. Every
     * non-spec route is identical to dev/test.
     */
    @Bean
    @Profile("!dev & !test")
    SecurityWebFilterChain filterChain(final ServerHttpSecurity http,
                                       final ModStepUpAccessDeniedHandler stepUpAccessDenied) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .headers(SecurityConfig::hardenedHeaders)
                .exceptionHandling(e -> e.accessDeniedHandler(stepUpAccessDenied))
                .authorizeExchange(ex -> {
                    commonRoutes(ex);
                    ex.pathMatchers(SPEC_PATHS).hasAnyRole("ADMIN", "SUPERADMIN");
                    ex.anyExchange().authenticated();
                })
                .oauth2ResourceServer(this::configureResourceServer)
                .build();
    }

    /**
     * Wire the resource server. Multi-issuer is OPT-IN: swap to the per-issuer
     * authentication-manager resolver ONLY when BOTH a resolver was contributed by
     * {@link TenancyResourceServerConfig} AND the registry is genuinely multi-issuer
     * (more than the lone back-compat entry). Gating on {@code isMultiIssuer()} — not
     * merely {@code resolver != null} — keeps a single-issuer cluster on the EXISTING
     * issuer-uri {@code o.jwt(...)} decoder path even if the tenancy conditional ever
     * activates with just the lone back-compat issuer. In true multi-brand mode each
     * trusted per-brand Casdoor validates its own tokens (unknown iss -> 401,
     * fail-closed).
     *
     * <p><b>{@code bearerTokenConverter} skip-guard for opaque {@code bff_} sessions.</b>
     * {@link BffCookieAuthenticationWebFilter} (this service's own bridge, {@code
     * @Order(HIGHEST_PRECEDENCE + 10)}, runs BEFORE this chain) already resolves an
     * opaque {@code bff_} session — carried either as the {@code bff_session} cookie or
     * as an {@code Authorization: Bearer bff_...} header — into a real {@code
     * Authentication} written to the {@code SecurityContext}. WITHOUT the guard below,
     * Spring's STOCK bearer-token extraction (installed by default on either branch
     * above) still grabs that SAME {@code Authorization: Bearer bff_...} header itself,
     * hands the opaque token to the JWT decoder, which fails ("Invalid JWT
     * serialization: Missing dot delimiter(s)"), and the resource server's own failure
     * handler commits a 401 DIRECTLY — overriding the SecurityContext the filter just
     * populated. Net effect: the header carrier for a bff_ token 401s end-to-end; only
     * the cookie carrier works (a bare cookie is invisible to the stock bearer-token
     * converter, so it finds nothing and contributes no authentication, leaving the
     * filter's context standing). {@link #skipBffTokenConverter()} closes that gap by
     * returning {@code Mono.empty()} (== "no bearer present") for a {@code bff_}-prefixed
     * Bearer, for EITHER branch below, so the resource server never attempts to
     * JWT-decode it; app-layer (the filter above) is the sole resolver of a bff_
     * session. A real Casdoor JWT Bearer is completely unaffected.
     */
    private void configureResourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec o) {
        o.bearerTokenConverter(skipBffTokenConverter());
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                tenantAuthManagerResolver.getIfAvailable();
        if (resolver != null && domainRegistry.isMultiIssuer()) {
            o.authenticationManagerResolver(resolver);
        } else {
            o.jwt(j -> j.jwtAuthenticationConverter(jwtConverter()));
        }
    }

    /**
     * A bearer-token converter that resolves a Casdoor JWT Bearer normally but returns
     * EMPTY for an opaque {@link BffCookieAuthenticationWebFilter#BFF_PREFIX}-prefixed
     * Bearer — so the resource server never attempts to JWT-decode a bff_ session token
     * (it is resolved at the app layer, by {@link BffCookieAuthenticationWebFilter},
     * instead). Empty == "no bearer present" to the resource server, so a bff_-only
     * request is treated as unauthenticated-by-bearer and the {@code authorizeExchange}
     * rules (permitAll / authenticated) apply exactly as if no Bearer had been sent —
     * letting the filter's already-populated SecurityContext stand. References {@link
     * BffCookieAuthenticationWebFilter#BFF_PREFIX} rather than re-declaring {@code
     * "bff_"} as a second, driftable literal (EXACT port of admin-bff-api's
     * {@code SecurityConfig.skipBffTokenConverter}, the already-merged reference fix for
     * this same gap).
     */
    private static ServerAuthenticationConverter skipBffTokenConverter() {
        ServerBearerTokenAuthenticationConverter delegate = new ServerBearerTokenAuthenticationConverter();
        return exchange -> {
            String auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
            if (auth != null && auth.startsWith("Bearer ")
                    && auth.substring(7).trim().startsWith(BffCookieAuthenticationWebFilter.BFF_PREFIX)) {
                return Mono.empty();   // opaque bff_ session -> not a JWT, app-layer resolves it.
            }
            return delegate.convert(exchange);
        };
    }

    /**
     * Method-security role hierarchy — SUPERADMIN-only edges, mirroring the sibling
     * forum-bff / wiki-bff config. {@code ROLE_SUPERADMIN} is a strict superset of
     * admin/mod/user; {@code ROLE_ADMIN} and {@code ROLE_MOD} stay documented SIBLINGS
     * (NO {@code ADMIN > MOD} edge — a plain ADMIN never silently becomes a MOD). Without
     * this bean the {@code /bff/mod/**} chain admits SUPERADMIN (see {@link #commonRoutes})
     * but every method-level {@code @PreAuthorize("hasAnyRole('MOD','ADMIN')")} REJECTS it
     * (only {@code /audit}, which lists SUPERADMIN explicitly, would pass) — contradicting
     * the documented "SUPERADMIN reaches every brand's surface" intent. This restores
     * that intent so the cross-domain infra superadmin can actually triage the queue.
     */
    @Bean
    RoleHierarchy roleHierarchy() {
        return RoleHierarchyImpl.fromHierarchy(
                "ROLE_SUPERADMIN > ROLE_ADMIN\n" +
                "ROLE_SUPERADMIN > ROLE_MOD\n" +
                "ROLE_SUPERADMIN > ROLE_USER");
    }

    /**
     * Wire {@link #roleHierarchy()} into REACTIVE method security so the
     * {@code @PreAuthorize("hasAnyRole('MOD','ADMIN')")} gates honour
     * {@code ROLE_SUPERADMIN > ROLE_ADMIN/ROLE_MOD}. A bare {@link RoleHierarchy} bean is
     * NOT auto-applied to {@code @PreAuthorize} in the reactive method-security path, so
     * the expression handler is set explicitly (same pattern as forum-bff / wiki-bff).
     */
    @Bean
    MethodSecurityExpressionHandler modMethodSecurityExpressionHandler(RoleHierarchy roleHierarchy) {
        DefaultMethodSecurityExpressionHandler handler = new DefaultMethodSecurityExpressionHandler();
        handler.setRoleHierarchy(roleHierarchy);
        // Keep the default ROLE_ prefix explicit so hasRole('ADMIN') maps to ROLE_ADMIN.
        handler.setDefaultRolePrefix(new GrantedAuthorityDefaults("ROLE_").getRolePrefix());
        return handler;
    }

    /**
     * The step-up gate the sensitive-write {@code @PreAuthorize} expressions call
     * ({@code @modStepUpGate.satisfied(authentication)} — see {@link net.hugmesh.modbff.ModController}).
     * Declared HERE, not as a {@code @Component}, so every slice that already imports this
     * config to activate method security gets the bean the expressions resolve against —
     * a stray {@code @Component} would leave those slices evaluating an unresolvable bean
     * reference.
     *
     * <p>{@code app.mfa.enforce-sensitive-writes} is a SEPARATE sub-flag from
     * {@code app.mfa.enabled} above (which governs only whether the converter DERIVES
     * {@code MFA_SATISFIED}), mirroring the gateway's {@code app.mfa.enforce-privileged-floor}
     * split. Default {@code false} ⇒ the gate is inert and the endpoints are unchanged.
     */
    @Bean
    ModStepUpGate modStepUpGate(
            @Value("${app.mfa.enforce-sensitive-writes:false}") boolean enforceSensitiveWrites) {
        return new ModStepUpGate(enforceSensitiveWrites);
    }

    /**
     * The chain's {@code accessDeniedHandler}, installed on BOTH profiles so the two cannot
     * drift. It is a PASS-THROUGH to Spring Security's default
     * {@code HttpStatusServerAccessDeniedHandler(FORBIDDEN)} for every refusal except the one
     * narrow case it exists for — an ARMED step-up gate refusing one of
     * {@link ModStepUpGate#SENSITIVE_WRITES} to a caller who DID pass the role half — which it
     * renders with the {@code X-Step-Up-Required} signal and the legacy phrase so
     * hugmesh-mod-ui can tell "you need a fresh second factor" from "you may not ban a
     * moderator". See hugmesh-mod-bff-api#16.
     *
     * <p>It changes no authorization rule: every {@code @PreAuthorize} expression and every
     * {@code authorizeExchange} rule above is untouched, and this handler runs only AFTER a
     * denial has already been decided. It can never turn a denial into a grant — it only ever
     * writes a 403.
     */
    @Bean
    ModStepUpAccessDeniedHandler modStepUpAccessDeniedHandler(ModStepUpGate modStepUpGate,
                                                             RoleHierarchy roleHierarchy) {
        return new ModStepUpAccessDeniedHandler(modStepUpGate, roleHierarchy);
    }

    private ReactiveJwtAuthenticationConverter jwtConverter() {
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(casdoorAuthoritiesConverter());
        return converter;
    }

    /**
     * Casdoor JWT -&gt; authorities conversion. Delegates to the shared
     * {@link CasdoorAuthorities} so the single-issuer path here and the optional
     * multi-issuer path ({@link TenancyResourceServerConfig}) stay byte-identical —
     * three claim sources ({@code roles} -&gt; {@code ROLE_<UPPER>}, {@code permissions}
     * verbatim minus the reserved {@code ROLE_}/{@code DOMAIN_} prefixes, legacy
     * {@code isAdmin} -&gt; {@code ROLE_ADMIN}), a {@code ROLE_USER} floor, plus exactly
     * one issuer-derived {@code DOMAIN_<x>} authority ({@code DOMAIN_default} for the
     * single-issuer fallback so this cluster is unchanged).
     */
    Converter<Jwt, Flux<GrantedAuthority>> casdoorAuthoritiesConverter() {
        return CasdoorAuthorities.converter(domainRegistry,
                new CasdoorAuthorities.MfaConfig(mfaEnabled, mfaFreshnessWindowMillis));
    }
}
