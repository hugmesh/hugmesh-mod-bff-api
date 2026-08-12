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
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.modbff.audit.ModAction;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.config.SecurityConfig;
import net.hugmesh.modbff.external.BlockOutcome;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.external.MatrixAdminClient;
import net.hugmesh.modbff.federation.FederationApiClient;
import net.hugmesh.modbff.service.ModService;
import net.hugmesh.modbff.web.ApiExceptionHandler;
import net.hugmesh.modbff.web.ValidationExceptionHandler;

import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-slice contract for the OWNCAST central-moderation surface
 * ({@code /bff/mod/owncast/streams/{owner}/hide|kill|restore}). The {@link ModService}
 * is mocked (its guards + honest-outcome flow are unit-tested in
 * {@code ModServiceOwncastTest}); these tests pin the HTTP contract:
 * <ul>
 *   <li>a synchronous OK effector outcome returns {@code 200 {state:'applied'}} (the
 *       owncast effect is NOT a reconcile-loop write);</li>
 *   <li>a degraded outcome returns {@code 202 {state:'not-applied'}} + the honest note
 *       — NEVER a 200;</li>
 *   <li>a plain USER is forbidden from all three verbs (the MOD floor);</li>
 *   <li>service-layer 403/404 ({@link ApiException}) surface as clean {error} bodies;</li>
 *   <li>an over-long reason is 400-bounded before the service.</li>
 * </ul>
 */
@WebFluxTest(controllers = ModController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class ModOwncastControllerTest {

    @Autowired ApplicationContext context;
    WebTestClient web;

    @BeforeEach
    void buildWebTestClient() {
        // Spring Security 7 (Boot 4): mockJwt() mutations require a WebTestClient bound
        // to the context WITH springSecurity() applied, else every request is 401.
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean FederationApiClient federation;
    @MockitoBean MatrixAdminClient matrix;
    @MockitoBean MastodonAdminClient mastodon;
    @MockitoBean ModActionRepository audit;
    @MockitoBean ModService mod;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private static ModService.OwncastModResult result(String action, BlockOutcome outcome) {
        ModAction row = new ModAction("o-1", "mod:bob", action, "owncast", "streamer:carol",
                "abuse", outcome.result(), LocalDateTime.parse("2026-06-06T00:00:00"));
        return new ModService.OwncastModResult(row, outcome);
    }

    // ── applied (synchronous OK) → 200 {state:'applied'} ────────────────

    @Test
    void hide_ok_returns200Applied() {
        when(mod.owncastHide(eq("streamer:carol"), eq("abuse"), any()))
                .thenReturn(Mono.just(result("owncast.hide", BlockOutcome.OK)));
        asMod().post().uri("/bff/mod/owncast/streams/streamer:carol/hide")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"abuse\"}")
                .exchange().expectStatus().isOk()
                .expectBody()
                .jsonPath("$.state").isEqualTo("applied")
                .jsonPath("$.external").isEqualTo("ok")
                .jsonPath("$.action.action").isEqualTo("owncast.hide");
    }

    @Test
    void kill_ok_returns200Applied_withKillVerb() {
        when(mod.owncastKill(eq("streamer:dave"), any(), any()))
                .thenReturn(Mono.just(result("owncast.kill", BlockOutcome.OK)));
        asMod().post().uri("/bff/mod/owncast/streams/streamer:dave/kill")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.action.action").isEqualTo("owncast.kill");
    }

    @Test
    void restore_ok_returns200_acceptsNoBody() {
        when(mod.owncastRestore(eq("streamer:dave"), any(), any()))
                .thenReturn(Mono.just(result("owncast.restore", BlockOutcome.OK)));
        asMod().post().uri("/bff/mod/owncast/streams/streamer:dave/restore")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.state").isEqualTo("applied");
    }

    // ── degraded → 202 not-applied (HONEST: never a 200) ────────────────

    @Test
    void kill_degraded_returns202NotApplied_withHonestNote() {
        when(mod.owncastKill(eq("streamer:dave"), any(), any()))
                .thenReturn(Mono.just(result("owncast.kill",
                        BlockOutcome.degraded("CallNotPermittedException"))));
        asMod().post().uri("/bff/mod/owncast/streams/streamer:dave/kill")
                .exchange().expectStatus().isAccepted()
                .expectBody()
                .jsonPath("$.state").isEqualTo("not-applied")
                .jsonPath("$.external").isEqualTo("degraded:CallNotPermittedException")
                .jsonPath("$.note").value(org.hamcrest.Matchers.containsString("NO reconcile loop"));
    }

    // ── MOD floor: plain USER forbidden on all three verbs ──────────────

    @Test
    void hide_forbiddenForPlainUser() {
        asUser().post().uri("/bff/mod/owncast/streams/streamer:carol/hide")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void kill_forbiddenForPlainUser() {
        asUser().post().uri("/bff/mod/owncast/streams/streamer:carol/kill")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void restore_forbiddenForPlainUser() {
        asUser().post().uri("/bff/mod/owncast/streams/streamer:carol/restore")
                .exchange().expectStatus().isForbidden();
    }

    // ── service-layer 403/404 surface as clean {error} bodies ───────────

    @Test
    void kill_selfTarget_surfaces403FromService() {
        when(mod.owncastKill(eq("mod:bob"), any(), any()))
                .thenReturn(Mono.error(ApiException.forbidden("a moderator may not ban themselves")));
        asMod().post().uri("/bff/mod/owncast/streams/mod:bob/kill")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("a moderator may not ban themselves");
    }

    @Test
    void hide_noStream_surfaces404FromService() {
        when(mod.owncastHide(eq("ghost"), any(), any()))
                .thenReturn(Mono.error(ApiException.notFound(
                        "target has no owncast stream in the moderator's brand")));
        asMod().post().uri("/bff/mod/owncast/streams/ghost/hide")
                .exchange().expectStatus().isNotFound()
                .expectBody().jsonPath("$.error")
                .isEqualTo("target has no owncast stream in the moderator's brand");
    }

    // ── validation: the reason note is bounded before the service ───────

    @Test
    void hide_400WhenReasonTooLong() {
        String longReason = "x".repeat(2049);
        asMod().post().uri("/bff/mod/owncast/streams/streamer:carol/hide")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"" + longReason + "\"}")
                .exchange().expectStatus().isBadRequest();
    }
}
