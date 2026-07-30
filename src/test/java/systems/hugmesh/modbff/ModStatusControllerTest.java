package systems.hugmesh.modbff;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.modbff.config.SecurityConfig;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.modbff.status.ModStatusController;
import systems.hugmesh.modbff.web.ApiExceptionHandler;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * FEAT-04 — moderator status polling endpoint contract tests.
 *
 * <ul>
 *   <li>Unauthenticated requests return 401.</li>
 *   <li>ROLE_USER is below the mod floor — 403.</li>
 *   <li>ROLE_MOD returns own status with roles and domain.</li>
 *   <li>ROLE_ADMIN also reaches the endpoint.</li>
 *   <li>Roles strip the ROLE_ prefix; DOMAIN_ authorities are not included in roles.</li>
 * </ul>
 */
@WebFluxTest(controllers = ModStatusController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ApiExceptionHandler.class})
class ModStatusControllerTest {

    @Autowired ApplicationContext context;
    WebTestClient web;

    @BeforeEach
    void buildWebTestClient() {
        // Spring Security 7 (Boot 4): mockJwt()/mock* mutations require a WebTestClient
        // bound to the context WITH springSecurity() applied, else every request is 401.
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @Test
    void status_anonymous_isUnauthorized() {
        web.get().uri("/bff/mod/status").exchange().expectStatus().isUnauthorized();
    }

    @Test
    void status_asUser_isForbidden() {
        web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                .get().uri("/bff/mod/status")
                .exchange()
                .expectStatus().isForbidden();
    }

    @Test
    void status_asMod_returnsStatus() {
        web.mutateWith(mockJwt()
                        .jwt(j -> j.subject("mod-alice"))
                        .authorities(
                                new SimpleGrantedAuthority("ROLE_MOD"),
                                new SimpleGrantedAuthority("ROLE_USER"),
                                new SimpleGrantedAuthority("DOMAIN_default")))
                .get().uri("/bff/mod/status")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.sub").isEqualTo("mod-alice")
                .jsonPath("$.domain").isEqualTo("default")
                .jsonPath("$.roles[?(@ == 'MOD')]").exists()
                .jsonPath("$.roles[?(@ == 'USER')]").exists()
                .jsonPath("$.roles[?(@ == 'DOMAIN_default')]").doesNotExist();
    }

    @Test
    void status_asAdmin_isAllowed() {
        web.mutateWith(mockJwt()
                        .jwt(j -> j.subject("admin-bob"))
                        .authorities(
                                new SimpleGrantedAuthority("ROLE_ADMIN"),
                                new SimpleGrantedAuthority("ROLE_USER"),
                                new SimpleGrantedAuthority("DOMAIN_default")))
                .get().uri("/bff/mod/status")
                .exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.sub").isEqualTo("admin-bob")
                .jsonPath("$.roles[?(@ == 'ADMIN')]").exists();
    }
}
