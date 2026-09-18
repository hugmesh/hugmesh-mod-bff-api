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
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.audit.ModAction;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.config.SecurityConfig;
import net.hugmesh.modbff.external.BlockOutcome;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.external.MatrixAdminClient;
import net.hugmesh.modbff.federation.FederationApiClient;
import net.hugmesh.modbff.service.ModService;
import net.hugmesh.modbff.web.ApiExceptionHandler;
import net.hugmesh.modbff.web.StepUpRequiredException;
import net.hugmesh.modbff.web.ValidationExceptionHandler;

import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * THE SHIPPED POSTURE: {@code app.mfa.enforce-sensitive-writes} is absent, i.e. its
 * production default {@code false}. Nothing in this repo asks to flip it, and #16 asked only
 * that the denial SAY more — not that more be denied.
 *
 * <p>So with the gate dark:
 * <ul>
 *   <li>a MOD with no {@code MFA_SATISFIED} marker still gets the normal 202 contract on the
 *       sensitive writes — no new denial appears;</li>
 *   <li>NO response carries {@value StepUpRequiredException#SIGNAL_HEADER}, not even the
 *       refusals on those same paths. A signal on a denial that never happens would be noise,
 *       and {@link net.hugmesh.modbff.security.ModStepUpAccessDeniedHandler} short-circuits on
 *       {@code isEnforced()} for exactly that reason.</li>
 * </ul>
 * The ARMED half of the story lives in {@link ModStepUpGateControllerTest}.
 */
@WebFluxTest(controllers = ModController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class ModStepUpSignalDarkTest {

    @Autowired ApplicationContext context;
    WebTestClient web;

    @BeforeEach
    void buildWebTestClient() {
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean FederationApiClient federation;
    @MockitoBean MatrixAdminClient matrix;
    @MockitoBean MastodonAdminClient mastodon;
    @MockitoBean ModActionRepository audit;
    @MockitoBean ModService mod;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    /** A fully-roled MOD carrying NO step-up marker — denied when armed, allowed when dark. */
    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD"),
                new SimpleGrantedAuthority("ROLE_MATRIX"), new SimpleGrantedAuthority("ROLE_MASTODON"),
                new SimpleGrantedAuthority("DOMAIN_default")));
    }

    private WebTestClient asPlainUser() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("DOMAIN_default")));
    }

    private static ModAction row(String action) {
        return new ModAction("s-1", "mod:bob", action, "access", "alice",
                "abuse", "pending", LocalDateTime.parse("2026-06-06T00:00:00"),
                "deadbeef", "user", null, "pending");
    }

    @Test
    void darkGate_stillAdmitsAModWithNoMarker_andSendsNoSignal() {
        when(mod.block(eq("matrix"), eq("user"), eq("@spam:evil.example"), any(), any()))
                .thenReturn(Mono.just(new ModService.BlockResult(row("matrix.block-user"), BlockOutcome.STUBBED)));

        asMod().post().uri("/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\",\"target\":\"@spam:evil.example\"}")
                .exchange()
                .expectStatus().isAccepted()
                .expectHeader().doesNotExist(StepUpRequiredException.SIGNAL_HEADER);
    }

    @Test
    void darkGate_aRoleRefusalOnAGatedPath_isStillBare() {
        asPlainUser().post().uri("/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\",\"target\":\"@spam:evil.example\"}")
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist(StepUpRequiredException.SIGNAL_HEADER);

        asPlainUser().method(org.springframework.http.HttpMethod.DELETE).uri("/bff/mod/ban")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"alice\"}")
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist(StepUpRequiredException.SIGNAL_HEADER);
    }
}
