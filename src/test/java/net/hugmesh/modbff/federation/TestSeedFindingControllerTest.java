package net.hugmesh.modbff.federation;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.config.SecurityConfig;
import net.hugmesh.modbff.web.ApiExceptionHandler;

import java.time.Instant;
import java.util.Map;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Slice test for {@link TestSeedFindingController} with {@code app.test-seed.enabled=true}
 * (the e2e/dev deployment configuration), importing the REAL {@link SecurityConfig} so the
 * {@code /bff/mod/**} MOD/ADMIN floor + {@code @PreAuthorize("hasAnyRole('MOD','ADMIN')")}
 * method gate are exercised; {@link FederationApiClient} is mocked.
 *
 * <ul>
 *   <li><b>USER-SITUATIONAL ALLOW</b> — an authenticated MOD or ADMIN seeds a finding
 *       through the SAME {@link FederationApiClient#fileFinding} the production
 *       pre-publish path would ultimately reach; the response carries the filed row.</li>
 *   <li><b>DEFAULTS</b> — an empty body falls back to the documented surface/disposition
 *       defaults.</li>
 *   <li><b>FAIL-CLOSED</b> — a plain USER is 403 (the SAME {@code /bff/mod/**} chain
 *       gate every other mod endpoint enforces) and anonymous is 401; the downstream
 *       client is NEVER reached on either.</li>
 * </ul>
 */
@WebFluxTest(controllers = TestSeedFindingController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ApiExceptionHandler.class})
@TestPropertySource(properties = "app.test-seed.enabled=true")
class TestSeedFindingControllerTest {

    @Autowired ApplicationContext context;
    WebTestClient client;

    @org.junit.jupiter.api.BeforeEach
    void setUpSecuredWebTestClient() {
        client = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean ReactiveJwtDecoder jwtDecoder;
    @MockitoBean FederationApiClient federation;

    private static final String PATH = "/bff/mod/findings/test-seed";

    private static SystemFindingDto sampleFinding(String surface, String disposition) {
        return new SystemFindingDto(42L, "@system", "mod-x", surface, disposition,
                null, null, null, null, "held", null, Instant.now(), "default");
    }

    // ── USER-SITUATIONAL ALLOW ───────────────────────────────────────────────
    @Nested
    class UserSituationalAllow {

        @Test
        void mod_seedsFinding_throughProductionFederationClient() {
            when(federation.fileFinding(eq("profile-avatar"), eq("flagged")))
                    .thenReturn(Mono.just(sampleFinding("profile-avatar", "flagged")));

            client.mutateWith(mockJwt().jwt(j -> j.subject("mod-x"))
                            .authorities(new SimpleGrantedAuthority("ROLE_MOD")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(new TestSeedFindingController.SeedRequest("profile-avatar", "flagged"))
                    .exchange()
                    .expectStatus().isOk()
                    .expectBody()
                    .jsonPath("$.id").isEqualTo(42)
                    .jsonPath("$.status").isEqualTo("held")
                    .jsonPath("$.surface").isEqualTo("profile-avatar");

            verify(federation).fileFinding("profile-avatar", "flagged");
        }

        @Test
        void admin_isAlsoAdmitted() {
            when(federation.fileFinding(eq("test-seed"), eq("flagged")))
                    .thenReturn(Mono.just(sampleFinding("test-seed", "flagged")));

            client.mutateWith(mockJwt().jwt(j -> j.subject("admin-x"))
                            .authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of())
                    .exchange()
                    .expectStatus().isOk();
        }
    }

    // ── DEFAULTS ──────────────────────────────────────────────────────────────
    @Nested
    class Defaults {

        @Test
        void emptyBody_fallsBackToDocumentedDefaults() {
            when(federation.fileFinding(eq(TestSeedFindingController.DEFAULT_SURFACE),
                    eq(TestSeedFindingController.DEFAULT_DISPOSITION)))
                    .thenReturn(Mono.just(sampleFinding(
                            TestSeedFindingController.DEFAULT_SURFACE,
                            TestSeedFindingController.DEFAULT_DISPOSITION)));

            client.mutateWith(mockJwt().jwt(j -> j.subject("mod-x"))
                            .authorities(new SimpleGrantedAuthority("ROLE_MOD")))
                    .post().uri(PATH)
                    .exchange()
                    .expectStatus().isOk();

            verify(federation).fileFinding(TestSeedFindingController.DEFAULT_SURFACE,
                    TestSeedFindingController.DEFAULT_DISPOSITION);
        }
    }

    // ── FAIL-CLOSED ───────────────────────────────────────────────────────────
    @Nested
    class FailClosed {

        @Test
        void plainUser_isForbidden_federationClientNeverReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("alice"))
                            .authorities(new SimpleGrantedAuthority("ROLE_USER")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of())
                    .exchange()
                    .expectStatus().isForbidden();

            verify(federation, never()).fileFinding(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
        }

        @Test
        void anonymous_isUnauthorized_federationClientNeverReached() {
            client.post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of())
                    .exchange()
                    .expectStatus().isUnauthorized();

            verify(federation, never()).fileFinding(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
        }

        @Test
        void badDisposition_isBadRequest_federationClientNeverReached() {
            client.mutateWith(mockJwt().jwt(j -> j.subject("mod-x"))
                            .authorities(new SimpleGrantedAuthority("ROLE_MOD")))
                    .post().uri(PATH)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue(Map.of("disposition", "not-a-real-disposition"))
                    .exchange()
                    .expectStatus().isBadRequest();

            verify(federation, never()).fileFinding(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
        }
    }
}
