package net.hugmesh.modbff;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.external.MatrixAdminClient;
import net.hugmesh.modbff.federation.FederationApiClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Context-load smoke test: boots the FULL application context under the {@code test}
 * profile and asserts the key beans are wired — the controller, the federation +
 * external homeserver clients, and the R2DBC audit repository. The {@code test}
 * profile points R2DBC at a throwaway in-mem H2 (Spring Boot auto-configures the
 * ConnectionFactory + DatabaseClient) and disables Liquibase, so no real datastore
 * is touched; a mocked {@link ReactiveJwtDecoder} stands in for live Casdoor so the
 * resource-server filter chain wires without a network call. This catches
 * bean-wiring / config regressions (the whole graph must construct) on top of the
 * focused slice tests.
 */
@SpringBootTest
@ActiveProfiles("test")
class ModBffApplicationTest {

    @MockitoBean ReactiveJwtDecoder jwtDecoder; // stands in for live Casdoor JWKS

    @Autowired ModController modController;
    @Autowired FederationApiClient federationApiClient;
    @Autowired MatrixAdminClient matrixAdminClient;
    @Autowired MastodonAdminClient mastodonAdminClient;
    @Autowired ModActionRepository modActionRepository;

    @Test
    void contextLoads_andKeyBeansAreWired() {
        assertThat(modController).isNotNull();
        assertThat(federationApiClient).isNotNull();
        assertThat(matrixAdminClient).isNotNull();
        assertThat(mastodonAdminClient).isNotNull();
        assertThat(modActionRepository).isNotNull();
    }
}
