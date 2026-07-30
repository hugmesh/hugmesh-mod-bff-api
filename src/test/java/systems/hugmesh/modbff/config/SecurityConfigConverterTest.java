package systems.hugmesh.modbff.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import reactor.core.publisher.Flux;
import systems.hugmesh.commons.security.DomainRegistry;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Unit test for the mod-BFF's Casdoor JWT → authority converter (delegating to the
 * shared {@link CasdoorAuthorities}, copied verbatim from hugmesh-gateway):
 * ROLE_USER floor; roles (string or {name}) → ROLE_&lt;UPPER&gt;; permissions verbatim
 * EXCEPT the reserved ROLE_/DOMAIN_ prefixes; isAdmin → ROLE_ADMIN; plus exactly one
 * issuer-derived DOMAIN_&lt;x&gt;. The {@code mod} role mapping to {@code ROLE_MOD} is
 * the one the mod-BFF gating depends on, so it is asserted explicitly.
 *
 * <p>USER-SITUATIONAL — a single token's full authority set per claim shape, on the
 * single-issuer (DOMAIN_default) back-compat path.
 */
class SecurityConfigConverterTest {

    @SuppressWarnings("unchecked")
    private SecurityConfig config(DomainRegistry registry) {
        // The optional multi-issuer resolver provider is empty for the single-issuer
        // converter under test.
        ObjectProvider<org.springframework.security.authentication.ReactiveAuthenticationManagerResolver<
                org.springframework.web.server.ServerWebExchange>> provider = mock(ObjectProvider.class);
        return new SecurityConfig(registry, provider, false, 600000L);
    }

    private List<String> authorities(Jwt jwt) {
        DomainRegistry reg = new DomainRegistry("https://id.hugmesh.systems", "");
        return config(reg).casdoorAuthoritiesConverter()
                .convert(jwt)
                .map(GrantedAuthority::getAuthority)
                .collectList()
                .block();
    }

    private static Jwt.Builder base() {
        return Jwt.withTokenValue("t").header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .issuer("https://id.hugmesh.systems")
                .subject("u");
    }

    @Test
    void floorIsRoleUser_plusDomainDefault() {
        assertThat(authorities(base().build()))
                .containsExactlyInAnyOrder("ROLE_USER", "DOMAIN_default");
    }

    @Test
    void stringRolesBecomeRolePrefixedUppercase_includingMod() {
        Jwt jwt = base().claim("roles", List.of("mod", "admin")).build();
        assertThat(authorities(jwt)).contains("ROLE_USER", "ROLE_MOD", "ROLE_ADMIN", "DOMAIN_default");
    }

    @Test
    void objectRolesWithNameAreMapped() {
        Jwt jwt = base().claim("roles", List.of(Map.of("name", "mod"))).build();
        assertThat(authorities(jwt)).contains("ROLE_MOD");
    }

    @Test
    void permissionsArePassedThroughVerbatim() {
        Jwt jwt = base().claim("permissions", List.of("urn:mod:block")).build();
        assertThat(authorities(jwt)).contains("urn:mod:block");
    }

    @Test
    void isAdminTrueAddsRoleAdmin() {
        Jwt jwt = base().claim("isAdmin", true).build();
        assertThat(authorities(jwt)).contains("ROLE_ADMIN");
    }

    @Test
    void converterReturnsFlux() {
        Flux<GrantedAuthority> flux = config(new DomainRegistry("https://id.hugmesh.systems", ""))
                .casdoorAuthoritiesConverter().convert(base().build());
        assertThat(flux.collectList().block()).isNotEmpty();
    }

    @Test
    void exactlyOneDomainAuthority_andItIsNonRole() {
        var names = authorities(base().claim("roles", List.of("mod")).build());
        assertThat(names).filteredOn(s -> s.startsWith("DOMAIN_")).hasSize(1);
        assertThat(names).noneMatch(s -> s.startsWith("ROLE_DOMAIN"));
    }
}
