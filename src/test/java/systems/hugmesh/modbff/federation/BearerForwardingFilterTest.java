package systems.hugmesh.modbff.federation;

import org.junit.jupiter.api.Test;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.context.Context;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The token-injecting filter forwards a real Casdoor JWT caller's bearer to the
 * downstream verbatim; attempts a best-effort custody exchange for a native-login
 * ({@code UsernamePasswordAuthenticationToken}) caller when a {@link
 * SessionExchangeService} is wired and a raw {@code bff_} token is on the Reactor
 * {@code Context}; and is a no-op (no header) in every other case — no Authentication at
 * all, a non-JWT/non-native-login Authentication, no exchange service wired, or no raw
 * token captured.
 */
class BearerForwardingFilterTest {

    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        @Override public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            return Mono.just(ClientResponse.create(HttpStatus.OK).body("{}").build());
        }
    }

    /** Minimal {@link ObjectProvider} test double — {@link ObjectProvider#getIfAvailable()}
     *  is the only method {@link BearerForwardingFilter} calls. */
    private static <T> ObjectProvider<T> providerOf(T value) {
        return new ObjectProvider<>() {
            @Override public T getObject() throws BeansException { return value; }
            @Override public T getObject(Object... args) throws BeansException { return value; }
            @Override public T getIfAvailable() throws BeansException { return value; }
            @Override public T getIfUnique() throws BeansException { return value; }
        };
    }

    private WebClient web(Recorder rec, ObjectProvider<SessionExchangeService> exchangeServiceProvider) {
        return WebClient.builder()
                .baseUrl("http://downstream.test")
                .filter(BearerForwardingFilter.forwardCallerToken(exchangeServiceProvider))
                .exchangeFunction(rec).build();
    }

    private WebClient web(Recorder rec) {
        return web(rec, providerOf(null));
    }

    private static Jwt jwt(String tokenValue) {
        return Jwt.withTokenValue(tokenValue).header("alg", "none")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600))
                .subject("mod:bob").build();
    }

    @Test
    void forwardsBearer_whenJwtOnContext() {
        Recorder rec = new Recorder();
        var auth = new JwtAuthenticationToken(jwt("the-token"),
                List.of(new SimpleGrantedAuthority("ROLE_MOD")));
        web(rec).get().uri("/x").retrieve().toBodilessEntity()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth))
                .block();
        assertThat(rec.requests).hasSize(1);
        assertThat(rec.requests.get(0).headers().getFirst(HttpHeaders.AUTHORIZATION))
                .isEqualTo("Bearer the-token");
    }

    @Test
    void noAuthHeader_whenNoJwtOnContext() {
        Recorder rec = new Recorder();
        web(rec).get().uri("/x").retrieve().toBodilessEntity().block();
        assertThat(rec.requests).hasSize(1);
        assertThat(rec.requests.get(0).headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
    }

    @Test
    void noAuthHeader_whenNonJwtNonNativeLoginAuthentication() {
        Recorder rec = new Recorder();
        var auth = new TestingAuthenticationToken("u", "p", "ROLE_USER");
        web(rec).get().uri("/x").retrieve().toBodilessEntity()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth))
                .block();
        assertThat(rec.requests.get(0).headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
    }

    @Test
    void noAuthHeader_forNativeLoginCaller_whenNoExchangeServiceWired() {
        // app.bff-exchange.enabled unset (the default) -> SessionExchangeConfig absent ->
        // ObjectProvider resolves to null -> fall through, exactly today's behaviour.
        Recorder rec = new Recorder();
        var auth = new UsernamePasswordAuthenticationToken(
                "casdoor:mod1", null, List.of(new SimpleGrantedAuthority("ROLE_MOD")));
        web(rec).get().uri("/x").retrieve().toBodilessEntity()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth))
                .contextWrite(ctx -> ctx.put(BffRawTokenContextWebFilter.CONTEXT_KEY, "bff_abc123"))
                .block();
        assertThat(rec.requests.get(0).headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
    }

    @Test
    void noAuthHeader_forNativeLoginCaller_whenNoRawTokenCaptured() {
        // Exchange service IS wired, but BffRawTokenContextWebFilter never ran (or found
        // nothing) -> nothing to exchange -> fall through.
        Recorder rec = new Recorder();
        SessionExchangeService alwaysSucceeds = new SessionExchangeService(
                rawToken -> Mono.just("should-never-be-used"), new SessionExchangeCache(5000, 10), Duration.ofSeconds(1));
        var auth = new UsernamePasswordAuthenticationToken(
                "casdoor:mod1", null, List.of(new SimpleGrantedAuthority("ROLE_MOD")));
        web(rec, providerOf(alwaysSucceeds)).get().uri("/x").retrieve().toBodilessEntity()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth))
                .block();
        assertThat(rec.requests.get(0).headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
    }

    @Test
    void forwardsExchangedBearer_forNativeLoginCaller_whenExchangeSucceeds() {
        Recorder rec = new Recorder();
        SessionExchangeService exchange = new SessionExchangeService(
                rawToken -> "bff_abc123".equals(rawToken) ? Mono.just("real-casdoor-jwt") : Mono.empty(),
                new SessionExchangeCache(5000, 10), Duration.ofSeconds(1));
        var auth = new UsernamePasswordAuthenticationToken(
                "casdoor:mod1", null, List.of(new SimpleGrantedAuthority("ROLE_MOD")));
        web(rec, providerOf(exchange)).get().uri("/x").retrieve().toBodilessEntity()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth))
                .contextWrite(ctx -> ctx.put(BffRawTokenContextWebFilter.CONTEXT_KEY, "bff_abc123"))
                .block();
        assertThat(rec.requests.get(0).headers().getFirst(HttpHeaders.AUTHORIZATION))
                .isEqualTo("Bearer real-casdoor-jwt");
    }

    @Test
    void noAuthHeader_forNativeLoginCaller_whenExchangeDegradesEmpty() {
        // Simulates every "soft" failure SessionExchangeService itself already collapses
        // to Mono.empty() (custody disabled / unknown session / suspended / transient).
        Recorder rec = new Recorder();
        SessionExchangeService exchange = new SessionExchangeService(
                rawToken -> Mono.empty(), new SessionExchangeCache(5000, 10), Duration.ofSeconds(1));
        var auth = new UsernamePasswordAuthenticationToken(
                "casdoor:mod1", null, List.of(new SimpleGrantedAuthority("ROLE_MOD")));
        web(rec, providerOf(exchange)).get().uri("/x").retrieve().toBodilessEntity()
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth))
                .contextWrite(ctx -> ctx.put(BffRawTokenContextWebFilter.CONTEXT_KEY, "bff_abc123"))
                .block();
        assertThat(rec.requests.get(0).headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
    }
}
