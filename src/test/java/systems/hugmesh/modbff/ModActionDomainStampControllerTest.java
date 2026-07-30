package systems.hugmesh.modbff;

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
import systems.hugmesh.modbff.audit.ModAction;
import systems.hugmesh.modbff.audit.ModActionRepository;
import systems.hugmesh.modbff.config.SecurityConfig;
import systems.hugmesh.modbff.external.MastodonAdminClient;
import systems.hugmesh.modbff.external.MatrixAdminClient;
import systems.hugmesh.modbff.federation.FederationApiClient;
import systems.hugmesh.modbff.federation.ModerationRequestDto;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.modbff.service.ModService;
import systems.hugmesh.modbff.web.ApiExceptionHandler;

import java.time.Instant;
import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * BUG-B — the {@code recommend}/{@code refer}/{@code block} mod actions must STAMP the
 * persisted {@code mod_action} row with the CALLER'S validated issuer-derived domain
 * ({@code DOMAIN_<x>}), so the brand's domain-scoped {@code GET /bff/mod/audit} read
 * ({@code listForDomain("<x>")}) can see them.
 *
 * <p>Before the fix these endpoints called the 6-arg {@code audit.record(...)} which
 * hard-stamps {@code domain='default'} ({@code ModActionRepository}), so a brand-X mod's
 * recommend/refer/block rows were stamped {@code 'default'} and were INVISIBLE to the
 * brand-X ADMIN's {@code listForDomain("brandx")} read. FAIL-FIRST: against the unfixed
 * 6-arg calls these {@code verify(...,"brandx")} assertions FAIL (the row is stamped
 * "default", not "brandx").
 *
 * <p>The READ half (a per-domain principal reads {@code listForDomain("brandx")}) is
 * proven in {@link ModAuditDomainScopeControllerTest}; this pins the WRITE half so the
 * two meet — a brand-X write is stamped {@code brandx} and is therefore returned by the
 * brand-X scoped read (asserted end-to-end in {@link #brandXRecommendRow_isReadableUnderBrandXScopedRead()}).
 */
@WebFluxTest(controllers = ModController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ApiExceptionHandler.class})
class ModActionDomainStampControllerTest {

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

    /** A brand-X MOD (issuer-derived DOMAIN_brandx) holding the platform roles. */
    private WebTestClient asBrandXMod() {
        return web.mutateWith(mockJwt().jwt(j -> j.subject("mod:x")).authorities(
                new SimpleGrantedAuthority("ROLE_MOD"),
                new SimpleGrantedAuthority("ROLE_MATRIX"),
                new SimpleGrantedAuthority("ROLE_MASTODON"),
                new SimpleGrantedAuthority("DOMAIN_brandx")));
    }

    private static ModerationRequestDto request(String status) {
        return new ModerationRequestDto(7L, "user:alice", "instance-block", "evil.example",
                "spam", status, null, null, Instant.parse("2026-06-06T00:00:00Z"));
    }

    private static ModAction row(String action, String domain) {
        return new ModAction("a-1", "mod:x", action, "federation", "evil.example",
                "spam", "ok", LocalDateTime.parse("2026-06-06T00:00:00"),
                null, null, null, null, domain);
    }

    // ── recommend stamps the caller's brand (NOT 'default') ────────────────────
    @Test
    void recommend_stampsRowWithCallersBrand() {
        when(federation.submitModeration(any())).thenReturn(Mono.just(request("recommended")));
        when(audit.record(anyString(), eq("federation.recommend"), eq("federation"),
                anyString(), any(), eq("ok"), eq("brandx")))
                .thenReturn(Mono.just(row("federation.recommend", "brandx")));
        asBrandXMod().post().uri("/bff/mod/moderation").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"instance-block\",\"target\":\"evil.example\",\"reason\":\"spam\"}")
                .exchange().expectStatus().isOk();
        // The row was stamped with the VALIDATED issuer-derived brand, not 'default'.
        verify(audit).record(eq("mod:x"), eq("federation.recommend"), eq("federation"),
                eq("evil.example"), eq("spam"), eq("ok"), eq("brandx"));
    }

    // ── refer stamps the caller's brand (NOT 'default') ────────────────────────
    @Test
    void refer_stampsRowWithCallersBrand() {
        when(federation.referModeration(7L)).thenReturn(Mono.just(request("referred")));
        when(audit.record(anyString(), eq("federation.refer"), eq("federation"),
                anyString(), any(), eq("ok"), eq("brandx")))
                .thenReturn(Mono.just(row("federation.refer", "brandx")));
        asBrandXMod().post().uri("/bff/mod/moderation/7/refer")
                .exchange().expectStatus().isOk();
        verify(audit).record(eq("mod:x"), eq("federation.refer"), eq("federation"),
                eq("moderation-request:7"), any(), eq("ok"), eq("brandx"));
    }

    // ── END-TO-END: a brand-X recommend row is RETURNED by the brand-X scoped read ──
    @Test
    void brandXRecommendRow_isReadableUnderBrandXScopedRead() {
        // WRITE: a brand-X recommend stamps the row 'brandx' (the fix).
        when(federation.submitModeration(any())).thenReturn(Mono.just(request("recommended")));
        when(audit.record(anyString(), eq("federation.recommend"), eq("federation"),
                anyString(), any(), eq("ok"), eq("brandx")))
                .thenReturn(Mono.just(row("federation.recommend", "brandx")));
        asBrandXMod().post().uri("/bff/mod/moderation").contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{\"kind\":\"instance-block\",\"target\":\"evil.example\",\"reason\":\"spam\"}")
                .exchange().expectStatus().isOk();
        verify(audit).record(eq("mod:x"), eq("federation.recommend"), eq("federation"),
                eq("evil.example"), eq("spam"), eq("ok"), eq("brandx"));

        // READ: the brand-X admin's domain-scoped read keys off the SAME 'brandx' predicate,
        // so the just-stamped row is returned. (With the pre-fix 'default' stamp it would
        // NOT match listForDomain("brandx") and the brand-X admin would never see it.)
        when(audit.listForDomain(eq("brandx"), anyInt()))
                .thenReturn(Flux.just(row("federation.recommend", "brandx")));
        asBrandXMod().get().uri("/bff/mod/audit").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[0].action").isEqualTo("federation.recommend")
                .jsonPath("$.actions[0].domain").isEqualTo("brandx");
    }
}
