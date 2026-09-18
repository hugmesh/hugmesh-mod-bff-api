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
import net.hugmesh.modbff.audit.ModActionType;
import net.hugmesh.modbff.config.SecurityConfig;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.external.BlockOutcome;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.federation.FederationApiClient;
import net.hugmesh.modbff.federation.ModerationRequestDto;
import net.hugmesh.modbff.federation.SystemFindingDto;
import net.hugmesh.modbff.service.ModService;
import net.hugmesh.modbff.web.ApiExceptionHandler;

import org.mockito.ArgumentCaptor;

import java.time.Instant;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * Moderator endpoint contract + role gating, reactive: @WebFluxTest + WebTestClient
 * + mockJwt() + a mocked ReactiveJwtDecoder to satisfy the resource-server wiring.
 * {@code @PreAuthorize} is active via @EnableReactiveMethodSecurity in
 * SecurityConfig (imported). CSRF is disabled, so POSTs need no token.
 *
 * <p>The gating story under test: a plain USER is FORBIDDEN from every mod
 * endpoint; a MOD is ALLOWED; an ADMIN is ALLOWED (the role analog of admin-bff).
 * The MOD path for a user-removal is REFER (escalate) — there is no direct-removal
 * endpoint to call, by design.
 */
@WebFluxTest(controllers = ModController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ApiExceptionHandler.class})
class ModControllerTest {

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
    @MockitoBean ReactiveJwtDecoder jwtDecoder; // satisfies oauth2 resource server wiring

    private WebTestClient asUser() {
        return web.mutateWith(mockJwt().authorities(new SimpleGrantedAuthority("ROLE_USER")));
    }

    /** A MOD that also holds the platform roles so the block() platform-role gate passes.
     *  Carries DOMAIN_default — the single-issuer tenant the converter would stamp — so
     *  the domain-scoped audit read resolves to "default". */
    private WebTestClient asMod() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_MOD"),
                new SimpleGrantedAuthority("ROLE_MATRIX"), new SimpleGrantedAuthority("ROLE_MASTODON"),
                new SimpleGrantedAuthority("DOMAIN_default")));
    }

    private WebTestClient asAdmin() {
        return web.mutateWith(mockJwt().authorities(
                new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("ROLE_ADMIN")));
    }

    private static ModerationRequestDto sampleRequest(String status) {
        return new ModerationRequestDto(7L, "user:alice", "instance-block", "evil.example",
                "spam", status, null, null, Instant.parse("2026-06-06T00:00:00Z"));
    }

    private static ModAction sampleAction(String action, String result) {
        return new ModAction("a-1", "mod:bob", action, "matrix", "@spam:evil.example",
                "abuse", result, LocalDateTime.parse("2026-06-06T00:00:00"));
    }

    // ── Moderation triage list ─────────────────────────────────────────
    @Test
    void listModeration_allowedForMod_returnsQueue() {
        when(federation.listModeration(null)).thenReturn(Flux.just(sampleRequest("recommended")));
        asMod().get().uri("/bff/mod/moderation").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.requests[0].id").isEqualTo(7)
                .jsonPath("$.requests[0].kind").isEqualTo("instance-block")
                .jsonPath("$.requests[0].status").isEqualTo("recommended");
    }

    @Test
    void listModeration_allowedForAdmin() {
        when(federation.listModeration(null)).thenReturn(Flux.empty());
        asAdmin().get().uri("/bff/mod/moderation").exchange().expectStatus().isOk();
    }

    @Test
    void listModeration_forbiddenForPlainUser() {
        asUser().get().uri("/bff/mod/moderation").exchange().expectStatus().isForbidden();
    }

    // ── Recommend (user→mod chain middle step) ─────────────────────────
    @Test
    void recommend_submitsToFederationAndAudits() {
        when(federation.submitModeration(any())).thenReturn(Mono.just(sampleRequest("recommended")));
        // BUG-B: recommend now records with the 7-arg (domain-stamped) record(...).
        when(audit.record(anyString(), anyString(), anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(sampleAction("federation.recommend", "ok")));
        asMod().post().uri("/bff/mod/moderation").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"instance-block\",\"target\":\"evil.example\",\"reason\":\"spam\"}")
                .exchange().expectStatus().isOk()
                .expectBody().jsonPath("$.request.kind").isEqualTo("instance-block");
    }

    @Test
    void recommend_400WhenMissingFields() {
        asMod().post().uri("/bff/mod/moderation").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"instance-block\"}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void recommend_forbiddenForPlainUser() {
        asUser().post().uri("/bff/mod/moderation").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"instance-block\",\"target\":\"evil.example\"}")
                .exchange().expectStatus().isForbidden();
    }

    // ── Refer-to-admin (the only mod removal path) ─────────────────────
    @Test
    void refer_escalatesToFederationAndAudits() {
        when(federation.referModeration(7L)).thenReturn(Mono.just(sampleRequest("referred")));
        // BUG-B: refer now records with the 7-arg (domain-stamped) record(...).
        when(audit.record(anyString(), eq("federation.refer"), anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(sampleAction("federation.refer", "ok")));
        asMod().post().uri("/bff/mod/moderation/7/refer").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.request.status").isEqualTo("referred");
    }

    @Test
    void refer_forbiddenForPlainUser() {
        asUser().post().uri("/bff/mod/moderation/7/refer").exchange().expectStatus().isForbidden();
    }

    // ── Server-wide block (external STUBBED, locally audited) ──────────
    @Test
    void block_matrixUser_stubbedReturns202NotBlocked_andAudited() {
        // The block flow now lives in ModService.block(...) (which runs the below-them /
        // cross-tenant guards before the external + audit effect); the controller maps a
        // non-OK BlockResult to 202. Here the service returns a STUBBED outcome.
        when(mod.block(eq("matrix"), eq("user"), eq("@spam:evil.example"), any(), any()))
                .thenReturn(Mono.just(new ModService.BlockResult(
                        sampleAction("matrix.block-user", "stubbed"), BlockOutcome.STUBBED)));
        // OUTCOME CONTRACT: a STUBBED external block did not land → 202 pending-reconcile,
        // NEVER 200 "blocked". The local audit row is still written.
        asMod().post().uri("/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\",\"target\":\"@spam:evil.example\",\"reason\":\"abuse\"}")
                .exchange().expectStatus().isAccepted()
                .expectBody()
                .jsonPath("$.state").isEqualTo("pending-reconcile")
                .jsonPath("$.external").isEqualTo("stubbed")
                .jsonPath("$.blocked.action").isEqualTo("matrix.block-user");
    }

    @Test
    void block_400WhenBadPlatformOrScope() {
        asMod().post().uri("/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"irc\",\"scope\":\"user\",\"target\":\"x\"}")
                .exchange().expectStatus().isBadRequest();
    }

    @Test
    void block_forbiddenForPlainUser() {
        asUser().post().uri("/bff/mod/block").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"platform\":\"matrix\",\"scope\":\"user\",\"target\":\"@x:y\"}")
                .exchange().expectStatus().isForbidden();
    }

    // ── Federation modules manifest ────────────────────────────────────
    @Test
    void modules_returnsManifest_forMod() {
        when(federation.manifest()).thenReturn(Mono.just(
                new net.hugmesh.modbff.federation.FederationManifestDto("2026-06-06T00:00:00Z", java.util.List.of())));
        asMod().get().uri("/bff/mod/modules").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.manifest.generatedAt").isEqualTo("2026-06-06T00:00:00Z");
    }

    @Test
    void modules_forbiddenForPlainUser() {
        asUser().get().uri("/bff/mod/modules").exchange().expectStatus().isForbidden();
    }

    // ── System-finding queue (automated edge-AI moderation) ────────────
    private static SystemFindingDto sampleFinding(String status, String reviewer) {
        return new SystemFindingDto(9L, "@system", "u:carol", "profile-avatar", "flagged",
                "nsfw", 0.91, true, "ph", status, reviewer, Instant.parse("2026-06-06T00:00:00Z"), "default");
    }

    @Test
    void listFindings_allowedForMod_returnsQueue() {
        when(federation.listFindings(null)).thenReturn(Flux.just(sampleFinding("held", null)));
        asMod().get().uri("/bff/mod/findings").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.findings[0].id").isEqualTo(9)
                .jsonPath("$.findings[0].reporter").isEqualTo("@system")
                .jsonPath("$.findings[0].surface").isEqualTo("profile-avatar")
                .jsonPath("$.findings[0].status").isEqualTo("held");
    }

    @Test
    void listFindings_withStatus_passesThrough_forAdmin() {
        when(federation.listFindings("held")).thenReturn(Flux.empty());
        asAdmin().get().uri("/bff/mod/findings?status=held").exchange().expectStatus().isOk();
    }

    @Test
    void listFindings_400WhenBadStatus() {
        asMod().get().uri("/bff/mod/findings?status=bogus").exchange().expectStatus().isBadRequest();
    }

    @Test
    void listFindings_forbiddenForPlainUser() {
        asUser().get().uri("/bff/mod/findings").exchange().expectStatus().isForbidden();
    }

    @Test
    void resolveFinding_actioned_proxiesAndAudits_withActionedDisposition() {
        when(federation.resolveFinding(9L, true)).thenReturn(Mono.just(sampleFinding("actioned", "mod:bob")));
        when(audit.record(anyString(), eq(ModActionType.FEDERATION_FINDING_RESOLVE), anyString(), anyString(),
                any(), anyString(), anyString()))
                .thenReturn(Mono.just(sampleAction(ModActionType.FEDERATION_FINDING_RESOLVE, "ok")));
        asMod().post().uri("/bff/mod/findings/9/resolve?actioned=true").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.finding.id").isEqualTo(9)
                .jsonPath("$.finding.status").isEqualTo("actioned")
                .jsonPath("$.finding.reviewer").isEqualTo("mod:bob");
        // The audit row records the disposition (actioned) in the reason slot + domain-stamps "default".
        ArgumentCaptor<String> reason = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> domain = ArgumentCaptor.forClass(String.class);
        verify(audit).record(anyString(), eq(ModActionType.FEDERATION_FINDING_RESOLVE), eq("federation"),
                eq("system-finding:9"), reason.capture(), eq("ok"), domain.capture());
        assertThat(reason.getValue()).isEqualTo("actioned");
        assertThat(domain.getValue()).isEqualTo("default");
    }

    @Test
    void resolveFinding_dismiss_recordsDismissedDisposition() {
        when(federation.resolveFinding(9L, false)).thenReturn(Mono.just(sampleFinding("dismissed", "mod:bob")));
        when(audit.record(anyString(), eq(ModActionType.FEDERATION_FINDING_RESOLVE), anyString(), anyString(),
                any(), anyString(), anyString()))
                .thenReturn(Mono.just(sampleAction(ModActionType.FEDERATION_FINDING_RESOLVE, "ok")));
        asMod().post().uri("/bff/mod/findings/9/resolve?actioned=false").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.finding.status").isEqualTo("dismissed");
        ArgumentCaptor<String> reason = ArgumentCaptor.forClass(String.class);
        verify(audit).record(anyString(), eq(ModActionType.FEDERATION_FINDING_RESOLVE), eq("federation"),
                eq("system-finding:9"), reason.capture(), eq("ok"), anyString());
        assertThat(reason.getValue()).isEqualTo("dismissed");
    }

    @Test
    void resolveFinding_400WhenActionedMissing() {
        asMod().post().uri("/bff/mod/findings/9/resolve").exchange().expectStatus().isBadRequest();
    }

    @Test
    void resolveFinding_forbiddenForPlainUser() {
        asUser().post().uri("/bff/mod/findings/9/resolve?actioned=true").exchange().expectStatus().isForbidden();
    }

    // ── Audit trail ────────────────────────────────────────────────────
    @Test
    void audit_returnsTrail_forMod_domainScoped() {
        // A per-domain MOD reads DOMAIN-SCOPED (listForDomain), NEVER the unscoped list()
        // — the cross-domain isolation boundary. This mod carries DOMAIN_default.
        when(audit.listForDomain(eq("default"), anyInt()))
                .thenReturn(Flux.just(sampleAction("matrix.block-user", "stubbed")));
        asMod().get().uri("/bff/mod/audit").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.actions[0].action").isEqualTo("matrix.block-user");
    }

    @Test
    void audit_forbiddenForPlainUser() {
        asUser().get().uri("/bff/mod/audit").exchange().expectStatus().isForbidden();
    }
}
