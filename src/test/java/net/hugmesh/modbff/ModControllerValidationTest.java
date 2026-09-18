package net.hugmesh.modbff;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.modbff.audit.ModAction;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.external.BlockOutcome;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.federation.FederationApiClient;
import net.hugmesh.modbff.service.ModService;
import net.hugmesh.modbff.web.ApiExceptionHandler;
import net.hugmesh.modbff.web.ValidationExceptionHandler;

import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Bean-validation contract on the moderator endpoints after the Map-body → typed-DTO
 * migration. Asserts the clean-400 + structured field-error body, that an invalid
 * platform/scope/kind never reaches the external clients or the audit table, that a
 * case-insensitive platform/scope is accepted, and that the {@code status} query
 * param is charset/length bounded. Existing 200/forbidden behavior is covered in
 * {@link ModControllerTest}.
 */
@WebFluxTest(controllers = ModController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class ModControllerValidationTest {

    @Autowired ApplicationContext context;
    WebTestClient web;

    @BeforeEach
    void buildWebTestClient() {
        // Spring Security 7 (Boot 4): mockJwt()/mock* mutations require a WebTestClient
        // bound to the context WITH springSecurity() applied, else every request is 401.
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean FederationApiClient federation;
    @MockitoBean MastodonAdminClient mastodon;
    @MockitoBean ModActionRepository audit;
    @MockitoBean ModService mod;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    /** A MOD that also holds the platform roles so the block() platform-role gate passes. */
    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD"),
                new SimpleGrantedAuthority("ROLE_MATRIX"), new SimpleGrantedAuthority("ROLE_MASTODON")));
    }

    private static ModAction sampleAction(String action, String result) {
        return new ModAction("a-1", "mod:bob", action, "matrix", "@spam:evil.example",
                "abuse", result, LocalDateTime.parse("2026-06-06T00:00:00"));
    }

    // ── block validation ───────────────────────────────────────────────
    @Test
    void block_badPlatform_400WithFieldError_andNoExternalCall() {
        asMod().post().uri("/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"irc\",\"scope\":\"user\",\"target\":\"x\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody()
                .jsonPath("$.error").isEqualTo("validation failed")
                .jsonPath("$.fields.platform").exists();
        verify(mod, never()).block(anyString(), anyString(), anyString(), anyString(), any());
        verify(audit, never()).record(anyString(), anyString(), anyString(), anyString(), any(), anyString());
    }

    @Test
    void block_missingTarget_400() {
        asMod().post().uri("/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.target").exists();
    }

    @Test
    void block_mixedCasePlatformAndScope_isAccepted() {
        // After case-insensitive validation, the controller forwards the lower-cased
        // platform/scope to ModService.block(...); a STUBBED outcome → 202 (never 200).
        when(mod.block(eq("matrix"), eq("instance"), eq("evil.example"), any(), any()))
                .thenReturn(Mono.just(new ModService.BlockResult(
                        sampleAction("matrix.block-instance", "stubbed"), BlockOutcome.STUBBED)));
        asMod().post().uri("/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"MATRIX\",\"scope\":\"Instance\",\"target\":\"evil.example\"}")
                .exchange().expectStatus().isAccepted()
                .expectBody()
                .jsonPath("$.state").isEqualTo("pending-reconcile")
                .jsonPath("$.blocked.action").isEqualTo("matrix.block-instance");
    }

    // ── recommend validation ───────────────────────────────────────────
    @Test
    void recommend_badKind_400_andNoSubmit() {
        asMod().post().uri("/bff/mod/moderation").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"delete-everything\",\"target\":\"evil.example\"}")
                .exchange().expectStatus().isBadRequest()
                .expectBody().jsonPath("$.fields.kind").exists();
        verify(federation, never()).submitModeration(any());
    }

    @Test
    void recommend_validKind_submits() {
        when(federation.submitModeration(any())).thenReturn(Mono.just(
                new net.hugmesh.modbff.federation.ModerationRequestDto(
                        7L, "user:alice", "user-removal", "@bad:evil.example", "spam",
                        "recommended", null, null, java.time.Instant.parse("2026-06-06T00:00:00Z"))));
        // BUG-B: recommend now records with the 7-arg (domain-stamped) record(...).
        when(audit.record(anyString(), anyString(), anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(sampleAction("federation.recommend", "ok")));
        asMod().post().uri("/bff/mod/moderation").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"user-removal\",\"target\":\"@bad:evil.example\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.request.kind").isEqualTo("user-removal");
    }

    // ── status query-param validation ──────────────────────────────────
    @Test
    void listModeration_badStatusParam_400() {
        asMod().get().uri("/bff/mod/moderation?status=Not_A_Status!!").exchange()
                .expectStatus().isBadRequest();
        verify(federation, never()).listModeration(anyString());
    }

    @Test
    void listModeration_validStatusParam_passesThrough() {
        when(federation.listModeration("referred")).thenReturn(Flux.empty());
        asMod().get().uri("/bff/mod/moderation?status=referred").exchange()
                .expectStatus().isOk();
        verify(federation).listModeration("referred");
    }
}
