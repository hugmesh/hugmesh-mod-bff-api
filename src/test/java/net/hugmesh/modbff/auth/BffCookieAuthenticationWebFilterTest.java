package net.hugmesh.modbff.auth;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit contract for {@link BffCookieAuthenticationWebFilter} — mod-bff-api's
 * HTTP-resolving counterpart to admin-bff-api's local
 * {@code net.hugmesh.authcore.config.BffCookieAuthenticationWebFilterTest}, and to
 * the gateway's {@code BffSessionAuthFilterTest} where behaviour overlaps (authority
 * mapping, token extraction, fail-open/fail-closed rules) — resolving sessions via a
 * mocked {@link AdminBffSessionIntrospectClient} instead of a mocked AccountStore/raw
 * WebClient.
 */
class BffCookieAuthenticationWebFilterTest {

    private static final long TIMEOUT_MS = 2000;

    @SuppressWarnings("unchecked")
    private static ObjectProvider<AdminBffSessionIntrospectClient> providerOf(AdminBffSessionIntrospectClient c) {
        ObjectProvider<AdminBffSessionIntrospectClient> provider = mock(ObjectProvider.class);
        when(provider.getIfAvailable()).thenReturn(c);
        return provider;
    }

    private static BffSessionIntrospection intro(String id, boolean regComplete, List<String> roles,
                                                   String status, boolean mfa) {
        return new BffSessionIntrospection(id, "casdoor", roles, regComplete, status, mfa);
    }

    /**
     * Captures the Authentication present in the downstream SecurityContext, and —
     * critically — COUNTS invocations rather than just flagging a boolean: a filter bug
     * that calls {@code chain.filter(exchange)} twice (e.g. a stray {@code switchIfEmpty}
     * after a {@code Mono<Void>}-returning flatMap, which is ALWAYS "empty" since Void
     * never emits onNext) would look identical to a single call under a boolean flag,
     * but doubles the downstream side effects and fails once the response is already
     * committed in production.
     */
    private static final class CapturingChain implements WebFilterChain {
        final AtomicInteger forwarded = new AtomicInteger(0);
        final AtomicReference<Authentication> auth = new AtomicReference<>();

        @Override
        public Mono<Void> filter(ServerWebExchange exchange) {
            forwarded.incrementAndGet();
            return ReactiveSecurityContextHolder.getContext()
                    .map(SecurityContext::getAuthentication)
                    .doOnNext(auth::set)
                    .then();
        }
    }

    // ── happy path ─────────────────────────────────────────────────────────────

    @Test
    void validBffToken_populatesSecurityContext() {
        AdminBffSessionIntrospectClient client = mock(AdminBffSessionIntrospectClient.class);
        when(client.introspect("bff_abc123")).thenReturn(Mono.just(
                intro("casdoor:mod1", true, List.of("user", "mod"), "active", false)));

        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(client), TIMEOUT_MS);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/mod/audit")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_abc123")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNotNull();
        assertThat(chain.auth.get().isAuthenticated()).isTrue();
        assertThat(chain.auth.get().getName()).isEqualTo("casdoor:mod1");

        var authorities = chain.auth.get().getAuthorities().stream().map(a -> a.getAuthority()).toList();
        assertThat(authorities).containsExactlyInAnyOrder("ROLE_USER", "ROLE_MOD");
    }

    @Test
    void validBffToken_viaCookieCarrier_populatesSecurityContext() {
        // mod-bff-api has no SessionCookieWebFilter carrier normalisation of its own —
        // the filter must read the bff_session cookie directly too.
        AdminBffSessionIntrospectClient client = mock(AdminBffSessionIntrospectClient.class);
        when(client.introspect("bff_cookievalue")).thenReturn(Mono.just(
                intro("casdoor:mod2", true, List.of("mod"), "active", false)));

        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(client), TIMEOUT_MS);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/mod/audit")
                .cookie(new HttpCookie("bff_session", "bff_cookievalue"))
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNotNull();
        assertThat(chain.auth.get().getName()).isEqualTo("casdoor:mod2");
    }

    // ── no bff_ token: Casdoor JWT bearer → pass-through, no client call ─────────

    @Test
    void casdoorJwtBearer_isNotABffToken_passesThrough_withoutCallingClient() {
        AdminBffSessionIntrospectClient client = mock(AdminBffSessionIntrospectClient.class);
        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(client), TIMEOUT_MS);

        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/mod/audit")
                .header(HttpHeaders.AUTHORIZATION, "Bearer eyJhbGciOiJSUzI1NiJ9....")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
        verify(client, never()).introspect(anyString());
    }

    @Test
    void noToken_passesThrough_unauthenticated() {
        AdminBffSessionIntrospectClient client = mock(AdminBffSessionIntrospectClient.class);
        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(client), TIMEOUT_MS);

        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/mod/audit").build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
        verify(client, never()).introspect(anyString());
    }

    @Test
    void bearerNonBffToken_notExtracted_noClientCall() {
        AdminBffSessionIntrospectClient client = mock(AdminBffSessionIntrospectClient.class);
        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(client), TIMEOUT_MS);

        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/mod/audit")
                .header(HttpHeaders.AUTHORIZATION, "not-even-bearer bff_abc123")
                .build();
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(MockServerWebExchange.from(req), chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
        verify(client, never()).introspect(anyString());
    }

    // ── no client bean available (e.g. a slice-test context) → pass-through ──────

    @Test
    void noClientAvailable_passesThrough_unauthenticated() {
        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(null), TIMEOUT_MS);

        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/mod/audit")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_abc123")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
    }

    // ── unknown/expired bff_ token (admin-bff 401) → pass-through unauthenticated ──

    @Test
    void unknownToken_401FromAdminBff_passesThrough_unauthenticated() {
        AdminBffSessionIntrospectClient client = mock(AdminBffSessionIntrospectClient.class);
        when(client.introspect("bff_expired")).thenReturn(Mono.error(
                WebClientResponseException.create(401, "Unauthorized", HttpHeaders.EMPTY, new byte[0], null)));

        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(client), TIMEOUT_MS);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/mod/audit")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_expired")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        assertThat(chain.auth.get()).isNull();
        assertThat(exchange.getResponse().getStatusCode()).isNull(); // untouched — downstream decides
    }

    // ── incomplete registration → restricted authority set ──────────────────────

    @Test
    void incompleteRegistration_onlyRoleUser_noModAuthority() {
        AdminBffSessionIntrospectClient client = mock(AdminBffSessionIntrospectClient.class);
        when(client.introspect("bff_newmod")).thenReturn(Mono.just(
                intro("casdoor:newmod", false, List.of("user", "mod"), "active", false)));

        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(client), TIMEOUT_MS);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/mod/audit")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_newmod")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        var authorities = chain.auth.get().getAuthorities().stream().map(a -> a.getAuthority()).toList();
        assertThat(authorities).containsExactly("ROLE_USER");
    }

    // ── MFA satisfied ─────────────────────────────────────────────────────────────

    @Test
    void mfaSatisfied_addsMfaSatisfiedAuthority() {
        AdminBffSessionIntrospectClient client = mock(AdminBffSessionIntrospectClient.class);
        when(client.introspect("bff_mfatoken")).thenReturn(Mono.just(
                intro("casdoor:mfamod", true, List.of("mod"), "active", true)));

        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(client), TIMEOUT_MS);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/mod/ban")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_mfatoken")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(1);
        var authorities = chain.auth.get().getAuthorities().stream().map(a -> a.getAuthority()).toList();
        assertThat(authorities).contains("MFA_SATISFIED", "ROLE_USER", "ROLE_MOD");
    }

    // ── suspended / banned → explicit 403, chain.filter() NEVER called ───────────

    @Test
    void suspendedAccount_forbidden_chainNeverCalled() {
        AdminBffSessionIntrospectClient client = mock(AdminBffSessionIntrospectClient.class);
        when(client.introspect("bff_suspended")).thenReturn(Mono.just(
                intro("casdoor:baduser", true, List.of("mod"), "suspended", false)));

        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(client), TIMEOUT_MS);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/mod/audit")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_suspended")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        // The deliberate short-circuit case: chain.filter() must be called ZERO times,
        // never one and never two — this is what distinguishes "forbidden" from both
        // the happy path AND the double-invocation bug class.
        assertThat(chain.forwarded.get()).isEqualTo(0);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getFirst("X-Bff-Denied")).isEqualTo("account-suspended");
    }

    @Test
    void bannedAccount_forbidden_chainNeverCalled() {
        AdminBffSessionIntrospectClient client = mock(AdminBffSessionIntrospectClient.class);
        when(client.introspect("bff_banned")).thenReturn(Mono.just(
                intro("casdoor:baduser2", true, List.of("admin"), "BANNED", false)));

        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(client), TIMEOUT_MS);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/mod/audit")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_banned")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(0);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getFirst("X-Bff-Denied")).isEqualTo("account-banned");
    }

    // ── admin-bff unreachable / 5xx → fail-closed 503, chain.filter() NEVER called ──

    @Test
    void backendError_failsClosed_503_chainNeverCalled() {
        AdminBffSessionIntrospectClient client = mock(AdminBffSessionIntrospectClient.class);
        when(client.introspect("bff_x")).thenReturn(Mono.error(
                WebClientResponseException.create(500, "Internal Server Error", HttpHeaders.EMPTY, new byte[0], null)));

        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(client), TIMEOUT_MS);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/mod/audit")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_x")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(0);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    void backendUnreachable_connectionError_failsClosed_503() {
        AdminBffSessionIntrospectClient client = mock(AdminBffSessionIntrospectClient.class);
        when(client.introspect("bff_x")).thenReturn(Mono.error(new IOException("connection refused")));

        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(client), TIMEOUT_MS);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/mod/audit")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_x")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).isEqualTo(0);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    @Test
    void introspectionTimesOut_failsClosed_503() {
        AdminBffSessionIntrospectClient client = mock(AdminBffSessionIntrospectClient.class);
        when(client.introspect("bff_slow")).thenReturn(Mono.never());

        // A short timeout so the test does not actually wait 2s.
        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(client), 30);
        MockServerHttpRequest req = MockServerHttpRequest.get("/bff/mod/audit")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_slow")
                .build();
        MockServerWebExchange exchange = MockServerWebExchange.from(req);
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain))
                .expectComplete()
                .verify(Duration.ofSeconds(2));

        assertThat(chain.forwarded.get()).isEqualTo(0);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
    }

    // ── decision resolution — unit tests on decide() directly ────────────────────

    @Test
    void decide_activeAccount_authenticates() {
        BffCookieAuthenticationWebFilter.Decision d = BffCookieAuthenticationWebFilter.decide(
                intro("casdoor:u1", true, List.of("mod"), "active", false));
        assertThat(d.kind()).isEqualTo(BffCookieAuthenticationWebFilter.Kind.AUTHENTICATE);
        assertThat(d.authentication()).isNotNull();
    }

    @Test
    void decide_suspendedAccount_forbidden() {
        BffCookieAuthenticationWebFilter.Decision d = BffCookieAuthenticationWebFilter.decide(
                intro("casdoor:u1", true, List.of("mod"), "suspended", false));
        assertThat(d.kind()).isEqualTo(BffCookieAuthenticationWebFilter.Kind.FORBIDDEN);
        assertThat(d.reason()).isEqualTo("suspended");
    }

    @Test
    void decide_bannedAccount_caseInsensitive_forbidden() {
        BffCookieAuthenticationWebFilter.Decision d = BffCookieAuthenticationWebFilter.decide(
                intro("casdoor:u1", true, List.of("mod"), "Banned", false));
        assertThat(d.kind()).isEqualTo(BffCookieAuthenticationWebFilter.Kind.FORBIDDEN);
        assertThat(d.reason()).isEqualTo("banned");
    }

    // ── allow-list: only an explicit "active" is granted; everything else fails CLOSED ──

    private static java.util.stream.Stream<String> notActiveStatuses() {
        return java.util.stream.Stream.of(
                null, "", "   ", "pending", "disabled", "locked", "deleted", "inactive",
                " active", "active ", "active\n", "activ", "actives", "ac\u0074ive\u200b",
                "active\r\nX-Evil: 1");
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.MethodSource("notActiveStatuses")
    void unknownOrMissingStatus_forbidden_chainNeverCalled(String status) {
        AdminBffSessionIntrospectClient client = mock(AdminBffSessionIntrospectClient.class);
        when(client.introspect("bff_unknown")).thenReturn(Mono.just(
                intro("casdoor:u", true, List.of("mod", "superadmin"), status, true)));

        BffCookieAuthenticationWebFilter f = new BffCookieAuthenticationWebFilter(providerOf(client), TIMEOUT_MS);
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/bff/mod/audit")
                .header(HttpHeaders.AUTHORIZATION, "Bearer bff_unknown").build());
        CapturingChain chain = new CapturingChain();

        StepVerifier.create(f.filter(exchange, chain)).verifyComplete();

        assertThat(chain.forwarded.get()).as("status=%s", status).isEqualTo(0);
        assertThat(exchange.getResponse().getStatusCode()).as("status=%s", status).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(exchange.getResponse().getHeaders().getFirst("X-Bff-Denied"))
                .as("status=%s", status).isEqualTo("account-status-unrecognized");
        assertThat(exchange.getResponse().getHeaders().getFirst("X-Evil")).isNull();
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {
            "{\"id\":\"casdoor:u\",\"roles\":[\"mod\"],\"registrationComplete\":true,\"mfaSatisfied\":true}",
            "{\"id\":\"casdoor:u\",\"roles\":[\"mod\"],\"registrationComplete\":true,\"status\":null}",
            "{\"id\":\"casdoor:u\",\"roles\":[\"mod\"],\"registrationComplete\":true,\"status\":\"pending\"}"})
    void wireBodyWithoutAnActiveStatus_decidesForbidden(String wireBody) throws Exception {
        BffSessionIntrospection parsed = new com.fasterxml.jackson.databind.ObjectMapper()
                .readValue(wireBody, BffSessionIntrospection.class);
        assertThat(BffCookieAuthenticationWebFilter.decide(parsed).kind())
                .isEqualTo(BffCookieAuthenticationWebFilter.Kind.FORBIDDEN);
    }

    @org.junit.jupiter.params.ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {"active", "ACTIVE", "Active"})
    void activeStatus_anyCase_isStillAuthenticated(String status) {
        assertThat(BffCookieAuthenticationWebFilter.decide(
                intro("casdoor:u1", true, List.of("mod"), status, false)).kind())
                .isEqualTo(BffCookieAuthenticationWebFilter.Kind.AUTHENTICATE);
    }

    // ── authority mapping unit tests ─────────────────────────────────────────────

    @Test
    void buildAuthorities_rolesMappedToUppercase_withFloor() {
        var authorities = BffCookieAuthenticationWebFilter
                .buildAuthorities(intro("casdoor:admin", true, List.of("user", "admin", "mod"), "active", false))
                .stream().map(a -> a.getAuthority()).toList();

        assertThat(authorities).containsExactlyInAnyOrder("ROLE_USER", "ROLE_ADMIN", "ROLE_MOD");
    }

    @Test
    void buildAuthorities_roleUserInRoles_notDuplicated() {
        var authorities = BffCookieAuthenticationWebFilter
                .buildAuthorities(intro("casdoor:u", true, List.of("user"), "active", false))
                .stream().map(a -> a.getAuthority()).toList();

        assertThat(authorities).containsExactly("ROLE_USER");
    }

    @Test
    void buildAuthorities_superadmin_isMapped() {
        var authorities = BffCookieAuthenticationWebFilter
                .buildAuthorities(intro("casdoor:sa", true, List.of("superadmin"), "active", false))
                .stream().map(a -> a.getAuthority()).toList();

        assertThat(authorities).contains("ROLE_SUPERADMIN", "ROLE_USER");
    }

    @Test
    void buildAuthorities_emptyRoles_onlyFloor() {
        var authorities = BffCookieAuthenticationWebFilter
                .buildAuthorities(intro("casdoor:norow", true, List.of(), "active", false))
                .stream().map(a -> a.getAuthority()).toList();

        assertThat(authorities).containsExactly("ROLE_USER");
    }
}
