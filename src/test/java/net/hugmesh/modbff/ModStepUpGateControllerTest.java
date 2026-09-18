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
import net.hugmesh.modbff.security.ModStepUpGate;
import net.hugmesh.modbff.security.Roles;
import net.hugmesh.modbff.service.ModService;
import net.hugmesh.modbff.web.ApiExceptionHandler;
import net.hugmesh.modbff.web.StepUpRequiredException;
import net.hugmesh.modbff.web.ValidationExceptionHandler;

import java.time.LocalDateTime;

import static org.hamcrest.Matchers.containsStringIgnoringCase;
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

    /** A caller with no moderator role at all — refused by the chain's {@code /bff/mod/**}
     *  rule on the very same paths, through the very same access-denied handler. */
    private WebTestClient asPlainUser() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("DOMAIN_default")));
    }

    /**
     * THE WIRE SHAPE OF A STEP-UP DENIAL — asserted on every one of the five, because the
     * whole defect (#16) was that a step-up refusal was indistinguishable from a role refusal.
     * Status stays 403 (unchanged), and the refusal now carries BOTH legs hugmesh-mod-ui
     * reads: the structured {@code X-Step-Up-Required} header whose value is this BFF's
     * flavour, and the legacy free-text phrase inside the {@code {"error": …}} body.
     */
    private static void expectStepUpSignal(WebTestClient.ResponseSpec response) {
        response.expectStatus().isForbidden()
                .expectHeader().valueEquals(StepUpRequiredException.SIGNAL_HEADER,
                        ModStepUpGate.STEP_UP_HEADER)
                .expectBody().jsonPath("$.error")
                        .value(containsStringIgnoringCase(StepUpRequiredException.LEGACY_PHRASE));
    }

    /** A denial that is NOT a step-up requirement must carry NO signal — otherwise mod-ui
     *  offers an MFA challenge that cannot possibly let the caller through. */
    private static void expectNoStepUpSignal(WebTestClient.ResponseSpec response) {
        response.expectHeader().doesNotExist(StepUpRequiredException.SIGNAL_HEADER);
    }

    // ── DENY: no step-up marker ⇒ 403 + the signal, and the service is never called ─────
    @Test
    void ban_forbiddenWithoutStepUp_andServiceNeverCalled() {
        expectStepUpSignal(asMod().post().uri("/bff/mod/ban").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"alice\",\"reason\":\"abuse\"}")
                .exchange());
        verify(mod, never()).ban(any(), any(), any(), any(), any(), any(), anyBoolean(), any());
    }

    @Test
    void lift_forbiddenWithoutStepUp() {
        expectStepUpSignal(asMod().method(org.springframework.http.HttpMethod.DELETE).uri("/bff/mod/ban")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"alice\"}")
                .exchange());
        verify(mod, never()).lift(any(), any(), any(), any());
    }

    @Test
    void block_forbiddenWithoutStepUp_andServiceNeverCalled() {
        expectStepUpSignal(asMod().post().uri("/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\",\"target\":\"@spam:evil.example\"}")
                .exchange());
        verify(mod, never()).block(any(), any(), any(), any(), any());
    }

    @Test
    void domainLock_forbiddenWithoutStepUp_andServiceNeverCalled() {
        expectStepUpSignal(asMod().post().uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/alice")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"reason\":\"abuse\"}")
                .exchange());
        verify(mod, never()).domainLock(any(), any(), any(), any(), any());
    }

    @Test
    void domainUnlock_forbiddenWithoutStepUp() {
        expectStepUpSignal(asMod().method(org.springframework.http.HttpMethod.DELETE)
                .uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/alice")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"reason\":\"abuse\"}")
                .exchange());
        verify(mod, never()).domainUnlock(any(), any(), any(), any());
    }

    /** {@code ModController} maps BOTH the bare and the trailing-slash spelling of
     *  domain-lock, so the handler's matcher has to carry both or one of the two gated
     *  shapes denies without a signal. */
    @Test
    void domainLock_trailingSlash_forbiddenWithoutStepUp_carriesTheSignal() {
        expectStepUpSignal(asMod().post().uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/alice/")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"reason\":\"abuse\"}")
                .exchange());
        verify(mod, never()).domainLock(any(), any(), any(), any(), any());
    }

    // ── NEGATIVE: a refusal that is NOT about step-up must stay bare ───────────
    /**
     * A plain {@code ROLE_USER} is refused on the SAME five paths by the chain's
     * {@code /bff/mod/**} rule, and that refusal reaches the very same access-denied handler.
     * It must NOT be dressed up as a step-up requirement: no second factor would ever let a
     * non-moderator ban somebody, so the dialog would be a dead end. This is the assertion
     * that makes the handler's role-half re-check load-bearing.
     */
    @Test
    void roleRefusal_onTheSameSensitivePaths_carriesNoSignal() {
        expectNoStepUpSignal(asPlainUser().post().uri("/bff/mod/block")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\",\"target\":\"@spam:evil.example\"}")
                .exchange().expectStatus().isForbidden());
        expectNoStepUpSignal(asPlainUser().post().uri("/bff/mod/ban")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"target\":\"alice\",\"reason\":\"abuse\"}")
                .exchange().expectStatus().isForbidden());
        expectNoStepUpSignal(asPlainUser().method(org.springframework.http.HttpMethod.DELETE)
                .uri("/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/alice")
                .contentType(MediaType.APPLICATION_JSON).bodyValue("{\"reason\":\"abuse\"}")
                .exchange().expectStatus().isForbidden());
    }

    /** A refusal on a NON-sensitive mod path carries no signal either — the signal is scoped
     *  to the five shapes that actually carry the conjunct. */
    @Test
    void refusalOnANonSensitivePath_carriesNoSignal() {
        expectNoStepUpSignal(asPlainUser().get().uri("/bff/mod/audit")
                .exchange().expectStatus().isForbidden());
        expectNoStepUpSignal(asPlainUser().get().uri("/bff/mod/moderation")
                .exchange().expectStatus().isForbidden());
    }

    /** An UNAUTHENTICATED caller gets 401, never a step-up offer: mod-ui deliberately does
     *  NOT recognise 401, because a challenge against a dead session cannot succeed. */
    @Test
    void unauthenticated_isNot403AndCarriesNoSignal() {
        expectNoStepUpSignal(web.post().uri("/bff/mod/block")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\",\"target\":\"@spam:evil.example\"}")
                .exchange().expectStatus().isUnauthorized());
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
