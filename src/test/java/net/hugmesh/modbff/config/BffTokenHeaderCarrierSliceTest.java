package net.hugmesh.modbff.config;

import net.hugmesh.commons.config.TenancyResourceServerConfig;
import net.hugmesh.commons.config.TenancyResolvers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterChainProxy;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.auth.AdminBffSessionIntrospectClient;
import net.hugmesh.modbff.auth.BffCookieAuthenticationWebFilter;
import net.hugmesh.modbff.auth.BffSessionIntrospection;
import net.hugmesh.modbff.testsupport.TestIssuer;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * BUG 1 regression — proves the {@code bff_} Authorization-HEADER carrier now reaches a
 * protected {@code /bff/mod/**} route end-to-end through the REAL production chain:
 * {@link BffCookieAuthenticationWebFilter} (mod-bff's own bridge, mirroring prod
 * ordering — installed AHEAD of the security chain, exactly like {@code @Order
 * (HIGHEST_PRECEDENCE + 10)} places it relative to Spring Security's {@code
 * WebFilterChainProxy}) followed by the REAL {@link SecurityConfig#filterChain} built
 * from a fresh {@link ServerHttpSecurity} (no full Spring context).
 *
 * <p>This is exactly the combination that was UNTESTED before this fix and let the bug
 * ship in the first place ({@code BffCookieAuthenticationWebFilterTest} exercises the
 * filter alone, never through the real chain; the chain-gate slices —
 * {@code SecurityConfigPathGateSliceTest} et al. — exercise real Casdoor JWTs, never a
 * bff_ token). Before the fix in {@code SecurityConfig#configureResourceServer}, Spring's
 * stock bearer-token extraction (no converter override) ALSO grabbed the {@code
 * Authorization: Bearer bff_...} header, handed it to the JWT decoder ("Invalid JWT
 * serialization: Missing dot delimiter(s)"), and the resource server's own failure
 * handler committed a 401 directly — overriding the SecurityContext the filter had
 * already populated. Only the {@code bff_session} COOKIE carrier worked (a bare cookie
 * is invisible to the stock bearer-token converter). This test sends the token ONLY as
 * the header (no cookie) and asserts 200 + that the mocked introspection client was
 * actually invoked, so a regression that silently stops calling it (rather than merely
 * mis-routing the response) would also be caught.
 *
 * <p>Multi-issuer resolver branch used purely so the chain can be BUILT (no full Boot
 * context; no live decoder needed) — see {@code SecurityConfigPathGateSliceTest}'s note
 * on why the single-issuer {@code o.jwt(...)} path can't be built in a no-network slice.
 * {@code o.bearerTokenConverter(skipBffTokenConverter())} is applied UNCONDITIONALLY in
 * {@code configureResourceServer} (before the branch), so this proves the fix on the
 * branch that is actually buildable here, and by inspection (see
 * {@code configureResourceServer}) the identical guard covers the single-issuer branch.
 */
class BffTokenHeaderCarrierSliceTest extends SecuritySliceSupport {

    private TestIssuer issuer;
    private TestIssuer issuer2;

    @BeforeEach
    void setUp() {
        issuer = new TestIssuer();
        issuer2 = new TestIssuer();
    }

    @AfterEach
    void tearDown() {
        issuer.close();
        issuer2.close();
    }

    @RestController
    static class ProbeController {
        @GetMapping("/bff/mod/reports")
        Mono<String> ok() {
            return Mono.just("ok");
        }
    }

    private WebTestClient clientWithBffFilter(AdminBffSessionIntrospectClient introspectClient) {
        String issuersCsv = issuer.issuerUri() + "=brandx," + issuer2.issuerUri() + "=brandy";
        DomainRegistry registry = new DomainRegistry(issuer.issuerUri(), issuersCsv);
        TenancyResourceServerConfig tenancy =
                new TenancyResourceServerConfig(registry, "", "", false, 600000L);
        ReactiveAuthenticationManagerResolver<ServerWebExchange> resolver =
                TenancyResolvers.tenantResolver(tenancy);

        SecurityConfig config = new SecurityConfig(registry, provider(resolver), false, 600000L);
        SecurityWebFilterChain chain = config.filterChain(ServerHttpSecurity.http());
        WebFilterChainProxy securityFilter = new WebFilterChainProxy(chain);

        @SuppressWarnings("unchecked")
        ObjectProvider<AdminBffSessionIntrospectClient> clientProvider = mock(ObjectProvider.class);
        when(clientProvider.getIfAvailable()).thenReturn(introspectClient);
        BffCookieAuthenticationWebFilter bffFilter =
                new BffCookieAuthenticationWebFilter(clientProvider, 2000);

        // Production ORDERING: the bff_ bridge runs AHEAD of the security chain
        // (HIGHEST_PRECEDENCE + 10 < the WebFilterChainProxy's default order), exactly
        // like CookieCsrfSliceTest mirrors admin-bff-api's own bridge-first ordering.
        return WebTestClient.bindToController(new ProbeController())
                .webFilter(bffFilter, securityFilter)
                .build();
    }

    @Test
    void bffTokenViaAuthorizationHeaderOnly_reachesProtectedModRoute_andInvokesIntrospection() {
        AdminBffSessionIntrospectClient introspectClient = mock(AdminBffSessionIntrospectClient.class);
        when(introspectClient.introspect("bff_headeronly123")).thenReturn(Mono.just(
                new BffSessionIntrospection("casdoor:mod1", "casdoor", List.of("mod"), true, "active", false)));

        WebTestClient client = clientWithBffFilter(introspectClient);

        // ONLY the Authorization header carrier — deliberately NO cookie — reaching a
        // route gated hasAnyRole("MOD","ADMIN","SUPERADMIN"). Before the fix this 401'd
        // (the stock bearer-token converter tried to JWT-decode the opaque bff_ token
        // and its failure handler overrode the filter's SecurityContext).
        client.get().uri("/bff/mod/reports")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_headeronly123")
                .exchange()
                .expectStatus().isOk();

        verify(introspectClient, times(1)).introspect(eq("bff_headeronly123"));
    }

    @Test
    void bffTokenViaAuthorizationHeaderOnly_insufficientRole_is403NotUnauthorized() {
        // A plain ROLE_USER bff_ session (no mod/admin) still AUTHENTICATES via the
        // header carrier (proving the SecurityContext really was populated, not merely
        // "not 401 because unauthenticated fell through to permitAll") but is correctly
        // REJECTED by the authorizeExchange policy: 403, not 401.
        AdminBffSessionIntrospectClient introspectClient = mock(AdminBffSessionIntrospectClient.class);
        when(introspectClient.introspect("bff_useronly")).thenReturn(Mono.just(
                new BffSessionIntrospection("casdoor:user1", "casdoor", List.of(), true, "active", false)));

        WebTestClient client = clientWithBffFilter(introspectClient);

        client.get().uri("/bff/mod/reports")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_useronly")
                .exchange()
                .expectStatus().isForbidden();

        verify(introspectClient, times(1)).introspect(eq("bff_useronly"));
    }

    @Test
    void realCasdoorJwtBearer_isUnaffectedByTheSkipGuard() {
        // A genuine Casdoor JWT (not bff_-prefixed) must still authenticate normally
        // through the SAME chain — the skip-guard only special-cases bff_ Bearers.
        AdminBffSessionIntrospectClient introspectClient = mock(AdminBffSessionIntrospectClient.class);
        WebTestClient client = clientWithBffFilter(introspectClient);

        String jwt = issuer.mint("p-mod", List.of("mod"));

        client.get().uri("/bff/mod/reports")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + jwt)
                .exchange()
                .expectStatus().isOk();

        // The bff_ introspection client is never consulted for a real JWT.
        assertThat(introspectClient).isNotNull();
        verify(introspectClient, org.mockito.Mockito.never()).introspect(org.mockito.ArgumentMatchers.anyString());
    }
}
