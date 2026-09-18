package net.hugmesh.modbff;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.config.SecurityConfig;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.external.MatrixAdminClient;
import net.hugmesh.modbff.federation.FederationApiClient;
import net.hugmesh.modbff.security.ModStepUpGate;
import net.hugmesh.modbff.service.ModService;
import net.hugmesh.modbff.web.ApiExceptionHandler;
import net.hugmesh.modbff.web.StepUpRequiredException;
import net.hugmesh.modbff.web.ValidationExceptionHandler;

import static org.hamcrest.Matchers.containsStringIgnoringCase;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * THE OTHER FILTER CHAIN. {@link SecurityConfig} builds two
 * {@code SecurityWebFilterChain} beans — {@code devFilterChain}
 * ({@code @Profile({"dev","test"})}) and {@code filterChain}
 * ({@code @Profile("!dev & !test")}) — and the step-up access-denied handler is installed
 * on BOTH so the two cannot drift. Every other slice in this repo (including
 * {@link ModStepUpGateControllerTest}) runs with no profile active and therefore only ever
 * exercises the PROD chain; a 2026-09-17 review measured that deleting
 * {@code .exceptionHandling(e -> e.accessDeniedHandler(stepUpAccessDenied))} from the
 * dev/test chain alone left the entire suite green. This class closes that: it is the same
 * slice with {@code @ActiveProfiles("test")}, so the dev/test chain is the one under test.
 *
 * <p>Impact is genuinely low — the compose stack runs {@code casdoor} and the cluster runs
 * profile-less, so both production paths take the prod chain — but {@code gen:fetch} and
 * local development take this one, and an unpinned claim in a javadoc is not a guard.
 *
 * @see ModStepUpGateControllerTest the same assertions against the prod chain
 */
@WebFluxTest(controllers = ModController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
@ActiveProfiles("test")
@TestPropertySource(properties = "app.mfa.enforce-sensitive-writes=true")
class ModStepUpSignalDevChainTest {

    @Autowired ApplicationContext context;
    WebTestClient web;

    @MockitoBean FederationApiClient federation;
    @MockitoBean MatrixAdminClient matrix;
    @MockitoBean MastodonAdminClient mastodon;
    @MockitoBean ModActionRepository audit;
    @MockitoBean ModService mod;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @BeforeEach
    void buildWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD"),
                new SimpleGrantedAuthority("ROLE_MATRIX"), new SimpleGrantedAuthority("DOMAIN_default")));
    }

    private WebTestClient asPlainUser() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("DOMAIN_default")));
    }

    /**
     * PROOF WE ARE ON THE DEV/TEST CHAIN, not the prod one — otherwise every assertion below
     * would silently be a duplicate of {@link ModStepUpGateControllerTest} and the drift this
     * class exists to catch would go on being invisible. The ONLY behavioural difference
     * between the two chains is {@code SPEC_PATHS}: public here, {@code hasAnyRole(ADMIN,
     * SUPERADMIN)} on the prod chain. An unauthenticated GET therefore falls through to "no
     * such handler in this slice" (404) here, where the prod chain would refuse it (401).
     */
    @Test
    void theChainUnderTestIsTheDevTestOne_specPathsArePublic() {
        web.get().uri("/v3/api-docs").exchange().expectStatus().isNotFound();
    }

    /** A step-up denial on the dev/test chain carries the same signal as on the prod chain. */
    @Test
    void stepUpDenial_onTheDevTestChain_carriesTheSignal() {
        asMod().post().uri("/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\",\"target\":\"@spam:evil.example\"}")
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().valueEquals(StepUpRequiredException.SIGNAL_HEADER,
                        ModStepUpGate.STEP_UP_HEADER)
                .expectBody().jsonPath("$.error")
                        .value(containsStringIgnoringCase(StepUpRequiredException.LEGACY_PHRASE));
    }

    /** And a role refusal on the dev/test chain stays bare, for the same reason it does on prod. */
    @Test
    void roleRefusal_onTheDevTestChain_carriesNoSignal() {
        asPlainUser().post().uri("/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\",\"target\":\"@spam:evil.example\"}")
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist(StepUpRequiredException.SIGNAL_HEADER);
    }
}
