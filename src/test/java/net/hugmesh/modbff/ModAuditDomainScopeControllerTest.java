package net.hugmesh.modbff;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.boot.webflux.test.autoconfigure.WebFluxTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Flux;
import net.hugmesh.modbff.audit.ModAction;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.config.SecurityConfig;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.external.MatrixAdminClient;
import net.hugmesh.modbff.federation.FederationApiClient;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.service.ModService;
import net.hugmesh.modbff.web.ApiExceptionHandler;

import java.time.LocalDateTime;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockJwt;
import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.springSecurity;

/**
 * DOMAIN-SCOPING of the {@code GET /bff/mod/audit} read at the WEB layer — the
 * cross-user isolation boundary as the HTTP surface enforces it. Delineated per the
 * test standard:
 *
 * <ul>
 *   <li>MULTIUSER-SITUATIONAL — a brand-X moderator reads the SCOPED query
 *       ({@code listForDomain("brandx")}), NEVER the unscoped {@code list()}; an admin
 *       likewise; {@code mine=true} narrows to the actor WITHIN the domain.</li>
 *   <li>CROSS-USER (NEGATIVE) — the controller passes the principal's OWN
 *       issuer-derived {@code DOMAIN_<x>} as the predicate, so a brand-X principal can
 *       only ever read brand-X rows; a principal with an ambiguous/zero DOMAIN_ set
 *       (the injection signature) resolves to a {@code null} domain and the scoped query
 *       returns empty (the repository's fail-closed contract).</li>
 *   <li>CROSS-USER (SUPERADMIN) — a SUPERADMIN reads UNSCOPED ({@code list()}) — the
 *       cross-domain infra control plane sees every brand.</li>
 * </ul>
 */
@WebFluxTest(controllers = ModController.class)
@Import({SecurityConfig.class, DomainRegistry.class, ApiExceptionHandler.class})
class ModAuditDomainScopeControllerTest {

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

    private WebTestClient as(SimpleGrantedAuthority... authorities) {
        return web.mutateWith(mockJwt().jwt(j -> j.subject("mod:bob")).authorities(authorities));
    }

    private static ModAction row(String domain) {
        return new ModAction("a-1", "mod:bob", "matrix.block-user", "matrix", "@x:y",
                "abuse", "stubbed", LocalDateTime.parse("2026-06-06T00:00:00"),
                null, null, null, null, domain);
    }

    // ── MULTIUSER-SITUATIONAL — a per-domain MOD reads its OWN brand only ──────
    @Test
    void modOfBrandX_readsScopedToBrandX_notUnscoped() {
        when(audit.listForDomain(eq("brandx"), anyInt())).thenReturn(Flux.just(row("brandx")));
        as(new SimpleGrantedAuthority("ROLE_MOD"), new SimpleGrantedAuthority("DOMAIN_brandx"))
                .get().uri("/bff/mod/audit").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[0].domain").isEqualTo("brandx");
        // The DENY half: the unscoped (cross-domain) list() is NEVER called for a
        // per-domain principal.
        verify(audit, never()).list(anyInt());
        verify(audit, never()).listByActor(org.mockito.ArgumentMatchers.anyString(), anyInt());
    }

    @Test
    void adminOfBrandY_readsScopedToBrandY() {
        when(audit.listForDomain(eq("brandy"), anyInt())).thenReturn(Flux.just(row("brandy")));
        as(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("DOMAIN_brandy"))
                .get().uri("/bff/mod/audit").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.actions[0].domain").isEqualTo("brandy");
        verify(audit).listForDomain(eq("brandy"), anyInt());
        verify(audit, never()).list(anyInt());
    }

    @Test
    void mineTrue_narrowsToActorWithinDomain() {
        when(audit.listByActorForDomain(eq("mod:bob"), eq("brandx"), anyInt())).thenReturn(Flux.just(row("brandx")));
        as(new SimpleGrantedAuthority("ROLE_MOD"), new SimpleGrantedAuthority("DOMAIN_brandx"))
                .get().uri("/bff/mod/audit?mine=true").exchange()
                .expectStatus().isOk();
        verify(audit).listByActorForDomain(eq("mod:bob"), eq("brandx"), anyInt());
        verify(audit, never()).listByActor(org.mockito.ArgumentMatchers.anyString(), anyInt());
    }

    // ── CROSS-USER (NEGATIVE) — an ambiguous DOMAIN_ set fails closed ──────────
    @Test
    void principalWithForgedSecondDomain_failsClosed_emptyRead() {
        // Two DOMAIN_ authorities (the injection signature) -> Roles.domainOf == null ->
        // listForDomain(null) -> empty. The principal sees NOTHING, never another brand.
        // (Defense-in-depth: the converter would have dropped the forged DOMAIN_ before
        // it ever reached here.)
        when(audit.listForDomain(eq((String) null), anyInt())).thenReturn(Flux.empty());
        as(new SimpleGrantedAuthority("ROLE_MOD"),
                new SimpleGrantedAuthority("DOMAIN_brandx"),
                new SimpleGrantedAuthority("DOMAIN_brandy"))
                .get().uri("/bff/mod/audit").exchange()
                .expectStatus().isOk()
                .expectBody().jsonPath("$.actions").isEmpty();
        verify(audit).listForDomain(eq((String) null), anyInt());
        verify(audit, never()).list(anyInt());
    }

    // ── CROSS-USER (SUPERADMIN) — unscoped, sees every brand ──────────────────
    @Test
    void superadmin_readsUnscoped_acrossEveryBrand() {
        when(audit.list(anyInt())).thenReturn(Flux.just(row("brandx"), row("brandy")));
        as(new SimpleGrantedAuthority("ROLE_SUPERADMIN"), new SimpleGrantedAuthority("DOMAIN_brandx"))
                .get().uri("/bff/mod/audit").exchange()
                .expectStatus().isOk()
                .expectBody()
                .jsonPath("$.actions[0].domain").isEqualTo("brandx")
                .jsonPath("$.actions[1].domain").isEqualTo("brandy");
        // SUPERADMIN uses the UNSCOPED query (cross-domain), NOT the per-domain one.
        verify(audit).list(anyInt());
        verify(audit, never()).listForDomain(org.mockito.ArgumentMatchers.anyString(), anyInt());
    }

    @Test
    void superadmin_mineTrue_unscopedByActor() {
        when(audit.listByActor(eq("mod:bob"), anyInt())).thenReturn(Flux.just(row("brandx")));
        as(new SimpleGrantedAuthority("ROLE_SUPERADMIN"), new SimpleGrantedAuthority("DOMAIN_brandx"))
                .get().uri("/bff/mod/audit?mine=true").exchange()
                .expectStatus().isOk();
        verify(audit).listByActor(eq("mod:bob"), anyInt());
        verify(audit, never()).listByActorForDomain(
                org.mockito.ArgumentMatchers.anyString(), org.mockito.ArgumentMatchers.any(), anyInt());
    }

    // ── The MOD floor still gates the surface (a plain USER is denied) ────────
    @Test
    void plainUser_isForbiddenFromAudit() {
        as(new SimpleGrantedAuthority("ROLE_USER"), new SimpleGrantedAuthority("DOMAIN_brandx"))
                .get().uri("/bff/mod/audit").exchange()
                .expectStatus().isForbidden();
    }

    // ── DoS GUARD: ?limit= is CLAMPED server-side before it reaches the repository ─────
    @Test
    void noLimitParam_passesTheServerDefaultToTheRepository() {
        // Absent ?limit= -> the controller passes the DEFAULT cap, never an unbounded read.
        when(audit.listForDomain(eq("brandx"), anyInt())).thenReturn(Flux.empty());
        as(new SimpleGrantedAuthority("ROLE_MOD"), new SimpleGrantedAuthority("DOMAIN_brandx"))
                .get().uri("/bff/mod/audit").exchange()
                .expectStatus().isOk();
        org.mockito.ArgumentCaptor<Integer> cap = org.mockito.ArgumentCaptor.forClass(Integer.class);
        verify(audit).listForDomain(eq("brandx"), cap.capture());
        org.assertj.core.api.Assertions.assertThat(cap.getValue())
                .isEqualTo(ModActionRepository.DEFAULT_AUDIT_LIMIT);
    }

    @Test
    void oversizedLimitParam_isClampedToTheHardCap_beforeTheRepository() {
        // An attacker-chosen huge ?limit= is clamped DOWN to MAX_AUDIT_LIMIT server-side.
        when(audit.listForDomain(eq("brandx"), anyInt())).thenReturn(Flux.empty());
        as(new SimpleGrantedAuthority("ROLE_MOD"), new SimpleGrantedAuthority("DOMAIN_brandx"))
                .get().uri("/bff/mod/audit?limit=999999").exchange()
                .expectStatus().isOk();
        org.mockito.ArgumentCaptor<Integer> cap = org.mockito.ArgumentCaptor.forClass(Integer.class);
        verify(audit).listForDomain(eq("brandx"), cap.capture());
        org.assertj.core.api.Assertions.assertThat(cap.getValue())
                .isEqualTo(ModActionRepository.MAX_AUDIT_LIMIT);
    }

    @Test
    void smallLimitParam_isPassedThroughVerbatim() {
        when(audit.listForDomain(eq("brandx"), anyInt())).thenReturn(Flux.empty());
        as(new SimpleGrantedAuthority("ROLE_MOD"), new SimpleGrantedAuthority("DOMAIN_brandx"))
                .get().uri("/bff/mod/audit?limit=10").exchange()
                .expectStatus().isOk();
        org.mockito.ArgumentCaptor<Integer> cap = org.mockito.ArgumentCaptor.forClass(Integer.class);
        verify(audit).listForDomain(eq("brandx"), cap.capture());
        org.assertj.core.api.Assertions.assertThat(cap.getValue()).isEqualTo(10);
    }
}
