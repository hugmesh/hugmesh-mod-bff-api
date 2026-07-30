package systems.hugmesh.modbff.federation;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.modbff.config.SecurityConfig;
import systems.hugmesh.modbff.web.ApiExceptionHandler;

import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * {@link TestSeedFindingController} in its DEFAULT (production) configuration —
 * {@code app.test-seed.enabled} is NOT set, so it falls back to {@code false}. Proves the
 * HONEST-DISCLOSURE invariant: a disabled seed route must not silently succeed while doing
 * nothing. Every call — even from a genuine, authenticated MOD/ADMIN principal — gets a
 * real 503 and {@link FederationApiClient} is NEVER reached (zero writes).
 *
 * <p>Separate test class (not a nested case in {@link TestSeedFindingControllerTest})
 * because the flag is read once at controller-construction time from {@code @Value}; a
 * distinct default-properties Spring context is the only way to exercise "flag genuinely
 * absent" rather than "flag explicitly true".
 */
@WebFluxTest(controllers = TestSeedFindingController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ApiExceptionHandler.class})
class TestSeedFindingControllerDisabledTest {

    @Autowired ApplicationContext context;
    WebTestClient client;

    @org.junit.jupiter.api.BeforeEach
    void setUpSecuredWebTestClient() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean FederationApiClient federation;

    private static final String PATH = "/bff/mod/findings/test-seed";

    @Test
    void defaultFlagOff_authenticatedMod_is503_federationClientNeverReached() {
        client.mutateWith(mockJwt().jwt(j -> j.subject("mod-x"))
                        .authorities(new SimpleGrantedAuthority("ROLE_MOD")))
                .post().uri(PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of())
                .exchange()
                .expectStatus().isEqualTo(503);

        verify(federation, never()).fileFinding(any(), any());
    }

    @Test
    void defaultFlagOff_authenticatedAdmin_is503_federationClientNeverReached() {
        client.mutateWith(mockJwt().jwt(j -> j.subject("admin-x"))
                        .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                .post().uri(PATH)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of())
                .exchange()
                .expectStatus().isEqualTo(503);

        verify(federation, never()).fileFinding(any(), any());
    }
}
