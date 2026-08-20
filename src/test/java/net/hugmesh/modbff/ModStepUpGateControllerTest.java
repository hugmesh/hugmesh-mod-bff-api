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
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;
import net.hugmesh.modbff.audit.ModAction;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.external.BlockOutcome;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.external.MatrixAdminClient;
import net.hugmesh.modbff.federation.FederationApiClient;
import net.hugmesh.modbff.security.Roles;
import net.hugmesh.modbff.service.ModService;
import net.hugmesh.modbff.web.ApiExceptionHandler;
import net.hugmesh.modbff.web.ValidationExceptionHandler;

import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Step-up MFA gate on the SENSITIVE mod write-effects, with the sub-flag ARMED
 * ({@code app.mfa.enforce-sensitive-writes=true}). The story under test:
 *
 * <ul>
 *   <li>a MOD/ADMIN WITHOUT the {@code MFA_SATISFIED} marker is 403 on block / ban /
 *       lift / domain-lock / domain-unlock — and the {@link ModService} is never
 *       reached, so no external effect and no audit row are produced;</li>
 *   <li>the SAME caller carrying {@code MFA_SATISFIED} passes the gate and gets the
 *       normal 202/200 contract;</li>
 *   <li>the NON-sensitive mod surface (reads + the moderation-queue write) is NOT
 *       gated even with the flag armed — the step-up requirement is scoped to the
 *       five irreversible-effect endpoints, not the whole BFF.</li>
 * </ul>
 *
 * <p>The DARK default (flag absent ⇒ no step-up required) is the posture every other
 * slice in this repo already asserts — {@code ModControllerTest} /
 * {@code ModBanControllerTest} drive the very same endpoints as a plain MOD with no
 * marker and expect 202/200 — so it is pinned there rather than duplicated here;
 * {@link net.hugmesh.modbff.security.ModStepUpGateTest} covers the predicate directly.
 */
@WebFluxTest(controllers = ModController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
@TestPropertySource(properties = "app.mfa.enforce-sensitive-writes=true")
class ModStepUpGateControllerTest {

    @Autowired ApplicationContext context;
    WebTestClient web;

    @BeforeEach
    void buildWebTestClient() {
        // Spring Security 7 (Boot 4): mockJwt()/mock* mutations require a WebTestClient
        // bound to the context WITH springSecurity() applied, else every request is 401.
        web = WebTestClient.bindToApplicationContext(context).apply(springSecurity()).build();
    }

    @MockitoBean FederationApiClient federation;
    @MockitoBean MatrixAdminClient matrix;
    @MockitoBean MastodonAdminClient mastodon;
    @MockitoBean ModActionRepository audit;
    @MockitoBean ModService mod;
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    /** A fully-roled MOD that has NOT completed a second factor — the deny case. */
    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD"),
                new SimpleGrantedAuthority("ROLE_MATRIX"), new SimpleGrantedAuthority("ROLE_MASTODON"),
                new SimpleGrantedAuthority("DOMAIN_default")));
    }

    /** The SAME MOD carrying the converter-derived / introspect-derived step-up marker. */
    private WebTestClient asSteppedUpMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD"),
                new SimpleGrantedAuthority("ROLE_MATRIX"), new SimpleGrantedAuthority("ROLE_MASTODON"),
                new SimpleGrantedAuthority("DOMAIN_default"),
                new SimpleGrantedAuthority(Roles.MFA_SATISFIED)));
    }

    private static ModAction row(String action) {
        return new ModAction("s-1", "mod:bob", action, "access", "alice",
                "abuse", "pending", LocalDateTime.parse("2026-06-06T00:00:00"),
                "deadbeef", "user", null, "pending");
    }

    // ── DENY: no step-up marker ⇒ 403, and the service is never called ─────────
    @Test
    void ban_forbiddenWithoutStepUp_andServiceNeverCalled() {
        asMod().post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"alice\",\"reason\":\"abuse\"}")
                .exchange().expectStatus().isForbidden();
        verify(mod, never()).ban(any(), any(), any(), any(), any(), any(), anyBoolean(), any());
    }

    @Test
    void lift_forbiddenWithoutStepUp() {
        asMod().method(org.springframework.http.HttpMethod.DELETE).uri("/bff/mod/ban")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"alice\"}")
                .exchange().expectStatus().isForbidden();
        verify(mod, never()).lift(any(), any(), any(), any());
    }

    @Test
    void block_forbiddenWithoutStepUp_andServiceNeverCalled() {
        asMod().post().uri("/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\",\"target\":\"@spam:evil.example\"}")
                .exchange().expectStatus().isForbidden();
        verify(mod, never()).block(any(), any(), any(), any(), any());
    }

    @Test
    void domainLock_forbiddenWithoutStepUp_andServiceNeverCalled() {
        asMod().post().uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/alice")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"reason\":\"abuse\"}")
                .exchange().expectStatus().isForbidden();
        verify(mod, never()).domainLock(any(), any(), any(), any(), any());
    }

    @Test
    void domainUnlock_forbiddenWithoutStepUp() {
        asMod().method(org.springframework.http.HttpMethod.DELETE)
                .uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/alice")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"abuse\"}")
                .exchange().expectStatus().isForbidden();
        verify(mod, never()).domainUnlock(any(), any(), any(), any());
    }

    // ── ALLOW: the same caller WITH the marker keeps the normal contract ───────
    @Test
    void ban_allowedWithStepUp_returns202() {
        when(mod.ban(eq("matrix"), eq("alice"), any(), any(), any(), any(), anyBoolean(), any()))
                .thenReturn(Mono.just(new ModService.BanResult(row("access.suspend"), "pending-reconcile", false)));
        asSteppedUpMod().post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"alice\",\"reason\":\"abuse\"}")
                .exchange().expectStatus().isAccepted()
                .expectBody().jsonPath("$.state").isEqualTo("pending-reconcile");
    }

    @Test
    void block_allowedWithStepUp_returns202Stubbed() {
        when(mod.block(eq("matrix"), eq("user"), eq("@spam:evil.example"), any(), any()))
                .thenReturn(Mono.just(new ModService.BlockResult(row("matrix.block-user"), BlockOutcome.STUBBED)));
        asSteppedUpMod().post().uri("/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\",\"target\":\"@spam:evil.example\"}")
                .exchange().expectStatus().isAccepted()
                .expectBody().jsonPath("$.state").isEqualTo("pending-reconcile");
    }

    @Test
    void domainLock_allowedWithStepUp_returns202() {
        when(mod.domainLock(eq("ROLE_MATRIX_DOMAINLOCKED"), eq("alice"), any(), any(), any()))
                .thenReturn(Mono.just(new ModService.LockResult(row("domain.lock"), "pending-reconcile", false)));
        asSteppedUpMod().post().uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/alice")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"reason\":\"abuse\"}")
                .exchange().expectStatus().isAccepted()
                .expectBody().jsonPath("$.state").isEqualTo("pending-reconcile");
    }

    // ── SCOPE: the non-sensitive surface is NOT step-up gated ─────────────────
    @Test
    void moderationQueueRead_notStepUpGated() {
        when(federation.listModeration(null)).thenReturn(reactor.core.publisher.Flux.empty());
        asMod().get().uri("/bff/mod/moderation").exchange().expectStatus().isOk();
    }
}
