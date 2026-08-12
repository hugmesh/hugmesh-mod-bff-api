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
import reactor.core.publisher.Mono;
import net.hugmesh.modbff.audit.ModAction;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.external.MatrixAdminClient;
import net.hugmesh.modbff.federation.FederationApiClient;
import net.hugmesh.modbff.service.ModService;
import net.hugmesh.commons.web.ApiException;
import net.hugmesh.modbff.web.ApiExceptionHandler;
import net.hugmesh.modbff.web.ValidationExceptionHandler;

import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Web-slice contract for the phase-2 ban surface + the platform-role gate on the
 * controller. The {@link ModService} is mocked here (its own guards are unit-tested
 * in {@code ModServiceTest}); these tests pin the HTTP contract:
 * <ul>
 *   <li>a ban returns {@code 202 {state:'pending-reconcile'}} (never 200);</li>
 *   <li>a plain USER is forbidden from the ban/lift surface (the MOD floor);</li>
 *   <li>a service-layer 403 ({@link ApiException}) surfaces as a clean 403 {error};</li>
 *   <li>the matrix/mastodon block path requires the platform role — a MOD WITHOUT
 *       ROLE_MATRIX/ROLE_MASTODON is 403 (the service throws; here the mock is set to
 *       throw to assert the controller surfaces it).</li>
 * </ul>
 */
@WebFluxTest(controllers = ModController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ValidationExceptionHandler.class, ApiExceptionHandler.class})
class ModBanControllerTest {

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

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD")));
    }

    private static ModAction banRow() {
        return new ModAction("b-1", "mod:bob", "access.suspend", "access", "alice",
                "abuse", "pending", LocalDateTime.parse("2026-06-06T00:00:00"),
                "deadbeef", "user", null, "pending");
    }

    private static ModService.BanResult pendingResult() {
        // pending-reconcile, not deduped — the body() the controller returns.
        return new ModService.BanResult(banRow(), "pending-reconcile", false);
    }

    // ── ban happy path → 202 pending-reconcile ─────────────────────────
    @Test
    void ban_returns202PendingReconcile_notBlocked() {
        when(mod.ban(eq("matrix"), eq("alice"), any(), any(), any(), any(), org.mockito.ArgumentMatchers.anyBoolean(), any()))
                .thenReturn(Mono.just(pendingResult()));
        asMod().post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"alice\",\"reason\":\"abuse\"}")
                .exchange().expectStatus().isAccepted()
                .expectBody()
                .jsonPath("$.state").isEqualTo("pending-reconcile")
                .jsonPath("$.action.action").isEqualTo("access.suspend");
    }

    // ── PR6: the notify directive is parsed + passed through to the service ──
    @Test
    void ban_withNotifyDirective_passesChannelsAndEmailOnlyToService() {
        org.mockito.ArgumentCaptor<java.util.List<String>> chans =
                org.mockito.ArgumentCaptor.forClass(java.util.List.class);
        when(mod.ban(eq("matrix"), eq("alice"), any(), any(), any(), chans.capture(),
                org.mockito.ArgumentMatchers.anyBoolean(), any()))
                .thenReturn(Mono.just(pendingResult()));
        asMod().post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"alice\",\"reason\":\"abuse\","
                        + "\"notifyChannels\":[\"in-app\",\"matrix\"],\"notifyEmailOnly\":false}")
                .exchange().expectStatus().isAccepted();
        org.assertj.core.api.Assertions.assertThat(chans.getValue())
                .containsExactly("in-app", "matrix");
    }

    @Test
    void ban_400WhenNotifyChannelMalformed() {
        // A channel token outside the bounded lower-alpha/hyphen shape → 400 before service.
        asMod().post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"alice\","
                        + "\"notifyChannels\":[\"NOT A CHANNEL!\"]}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void ban_forbiddenForPlainUser() {
        asUser().post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"alice\"}")
                .exchange().expectStatus().isForbidden();
    }

    @Test
    void ban_400WhenBadPlatform() {
        asMod().post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"irc\",\"target\":\"alice\"}")
                .exchange().expectStatus().isBadRequest();
    }

    // ── service-layer 403s surface as clean 403 {error} ────────────────
    @Test
    void ban_selfBan_surfaces403FromService() {
        when(mod.ban(eq("matrix"), eq("bob"), any(), any(), any(), any(), org.mockito.ArgumentMatchers.anyBoolean(), any()))
                .thenReturn(Mono.error(ApiException.forbidden("a moderator may not ban themselves")));
        asMod().post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"bob\"}")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("a moderator may not ban themselves");
    }

    @Test
    void ban_privilegedTarget_surfaces403FromService() {
        when(mod.ban(eq("mastodon"), eq("anadmin"), any(), any(), any(), any(), org.mockito.ArgumentMatchers.anyBoolean(), any()))
                .thenReturn(Mono.error(ApiException.forbidden(
                        "target holds ROLE_ADMIN or ROLE_MOD and cannot be banned by a moderator")));
        asMod().post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"mastodon\",\"target\":\"anadmin\"}")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error")
                .isEqualTo("target holds ROLE_ADMIN or ROLE_MOD and cannot be banned by a moderator");
    }

    // ── lift → 202 ─────────────────────────────────────────────────────
    @Test
    void lift_returns202() {
        when(mod.lift(eq("matrix"), eq("alice"), any(), any()))
                .thenReturn(Mono.just(new ModService.BanResult(
                        new ModAction("r-1", "mod:bob", "access.restore", "access", "alice",
                                null, "pending", LocalDateTime.parse("2026-06-06T00:00:00"),
                                "cafe", "user", null, "pending"),
                        "pending-reconcile", false)));
        asMod().method(org.springframework.http.HttpMethod.DELETE).uri("/bff/mod/ban")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"alice\"}")
                .exchange().expectStatus().isAccepted()
                .expectBody().jsonPath("$.action.action").isEqualTo("access.restore");
    }

    // ── block platform-role gate: service throws 403 → controller surfaces ─
    @Test
    void block_matrixWithoutPlatformRole_403() {
        // The block flow now lives in ModService.block(...) (which runs assertPlatformRole
        // internally, after the below-them/cross-tenant guards); simulate the service
        // surfacing the platform-role 403 (a MOD lacking ROLE_MATRIX) and assert the
        // controller relays it as a clean 403 {error}.
        when(mod.block(eq("matrix"), eq("user"), eq("@x:y"), any(), any()))
                .thenReturn(Mono.error(ApiException.forbidden(
                        "platform 'matrix' requires ROLE_MATRIX (or ROLE_ADMIN)")));
        asMod().post().uri("/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\",\"target\":\"@x:y\"}")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("platform 'matrix' requires ROLE_MATRIX (or ROLE_ADMIN)");
    }

    @Test
    void block_mastodonWithoutPlatformRole_403() {
        when(mod.block(eq("mastodon"), eq("user"), eq("@x@y"), any(), any()))
                .thenReturn(Mono.error(ApiException.forbidden(
                        "platform 'mastodon' requires ROLE_MASTODON (or ROLE_ADMIN)")));
        asMod().post().uri("/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"mastodon\",\"scope\":\"user\",\"target\":\"@x@y\"}")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("platform 'mastodon' requires ROLE_MASTODON (or ROLE_ADMIN)");
    }

    // ── domain-lock surface ────────────────────────────────────────────
    private static ModService.LockResult lockPending(String action) {
        ModAction row = new ModAction("d-1", "mod:bob", action, "domain-lock", "alice",
                null, "pending", LocalDateTime.parse("2026-06-06T00:00:00"),
                "feed", "user", null, "pending");
        return new ModService.LockResult(row, "pending-reconcile", false);
    }

    // ── domain-lock happy path → 202 pending-reconcile ─────────────────
    @Test
    void domainLock_returns202PendingReconcile_notLocked() {
        when(mod.domainLock(eq("ROLE_MATRIX_DOMAINLOCKED"), eq("alice"), any(), any(), any()))
                .thenReturn(Mono.just(lockPending("domain.lock")));
        asMod().post().uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/alice")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"reason\":\"abuse\"}")
                .exchange().expectStatus().isAccepted()
                .expectBody()
                .jsonPath("$.state").isEqualTo("pending-reconcile")
                .jsonPath("$.action.action").isEqualTo("domain.lock");
    }

    // ── domain-lock accepts a body-less POST (optional body) ───────────
    @Test
    void domainLock_acceptsNoBody() {
        when(mod.domainLock(eq("ROLE_MASTODON_DOMAINLOCKED"), eq("alice"), any(), any(), any()))
                .thenReturn(Mono.just(lockPending("domain.lock")));
        asMod().post().uri("/bff/mod/domain-lock/ROLE_MASTODON_DOMAINLOCKED/alice")
                .exchange().expectStatus().isAccepted();
    }

    @Test
    void domainLock_forbiddenForPlainUser() {
        asUser().post().uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/alice")
                .exchange().expectStatus().isForbidden();
    }

    // ── {role} path var is @Pattern-validated to the two domain-lock roles ─
    @Test
    void domainLock_400WhenBadRole() {
        asMod().post().uri("/bff/mod/domain-lock/ROLE_BOGUS/alice")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void domainLock_400WhenAccessRoleNotAllowed() {
        // A plain access role (e.g. ROLE_MATRIX) is NOT a domain-lock marker → 400.
        asMod().post().uri("/bff/mod/domain-lock/ROLE_MATRIX/alice")
                .exchange().expectStatus().isBadRequest();
    }

    // ── below-them guard surfaces as a clean 403 {error} ───────────────
    @Test
    void domainLock_privilegedTarget_surfaces403FromService() {
        when(mod.domainLock(eq("ROLE_MATRIX_DOMAINLOCKED"), eq("anadmin"), any(), any(), any()))
                .thenReturn(Mono.error(ApiException.forbidden(
                        "target holds ROLE_ADMIN or ROLE_MOD and cannot be banned by a moderator")));
        asMod().post().uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/anadmin")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error")
                .isEqualTo("target holds ROLE_ADMIN or ROLE_MOD and cannot be banned by a moderator");
    }

    @Test
    void domainLock_selfLock_surfaces403FromService() {
        when(mod.domainLock(eq("ROLE_MATRIX_DOMAINLOCKED"), eq("bob"), any(), any(), any()))
                .thenReturn(Mono.error(ApiException.forbidden("a moderator may not ban themselves")));
        asMod().post().uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/bob")
                .exchange().expectStatus().isForbidden()
                .expectBody().jsonPath("$.error").isEqualTo("a moderator may not ban themselves");
    }

    // ── domain-unlock → 202 ────────────────────────────────────────────
    @Test
    void domainUnlock_returns202() {
        when(mod.domainUnlock(eq("ROLE_MASTODON_DOMAINLOCKED"), eq("alice"), any(), any()))
                .thenReturn(Mono.just(lockPending("domain.unlock")));
        asMod().method(org.springframework.http.HttpMethod.DELETE)
                .uri("/bff/mod/domain-lock/ROLE_MASTODON_DOMAINLOCKED/alice")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{}")
                .exchange().expectStatus().isAccepted()
                .expectBody().jsonPath("$.action.action").isEqualTo("domain.unlock");
    }

    @Test
    void domainUnlock_forbiddenForPlainUser() {
        asUser().method(org.springframework.http.HttpMethod.DELETE)
                .uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/alice")
                .exchange().expectStatus().isForbidden();
    }
}
