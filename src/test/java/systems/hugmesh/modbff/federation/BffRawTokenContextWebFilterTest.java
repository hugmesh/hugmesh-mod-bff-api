package systems.hugmesh.modbff.federation;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpCookie;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * The raw {@code bff_} token is captured from the {@code Authorization} header first,
 * then the {@code bff_session} cookie — mirrors {@code BffCookieAuthenticationWebFilter}'s
 * own extraction exactly — and NEVER captured for a real JWT bearer or an anonymous
 * request.
 */
class BffRawTokenContextWebFilterTest {

    @Test
    void extractsFromAuthorizationHeader() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/x").header(HttpHeaders.AUTHORIZATION, "Bearer bff_abc123"));
        assertThat(BffRawTokenContextWebFilter.extractToken(exchange)).isEqualTo("bff_abc123");
    }

    @Test
    void extractsFromCookie_whenNoHeader() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/x").cookie(new HttpCookie("bff_session", "bff_fromcookie")));
        assertThat(BffRawTokenContextWebFilter.extractToken(exchange)).isEqualTo("bff_fromcookie");
    }

    @Test
    void headerTakesPriorityOverCookie() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/x")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer bff_fromheader")
                        .cookie(new HttpCookie("bff_session", "bff_fromcookie")));
        assertThat(BffRawTokenContextWebFilter.extractToken(exchange)).isEqualTo("bff_fromheader");
    }

    @Test
    void ignoresARealJwtBearer_evenWithABffCookiePresent() {
        // A real Casdoor JWT header short-circuits extraction (never falls back to the
        // cookie) — matches BffCookieAuthenticationWebFilter#extractToken exactly.
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/x")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer eyJhbGciOi.some.jwt")
                        .cookie(new HttpCookie("bff_session", "bff_fromcookie")));
        assertThat(BffRawTokenContextWebFilter.extractToken(exchange)).isNull();
    }

    @Test
    void nullForAnonymousRequest() {
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/x"));
        assertThat(BffRawTokenContextWebFilter.extractToken(exchange)).isNull();
    }

    @Test
    void filter_writesTheTokenIntoTheReactorContext_whenPresent() {
        ServerWebExchange exchange = MockServerWebExchange.from(
                MockServerHttpRequest.get("/x").header(HttpHeaders.AUTHORIZATION, "Bearer bff_abc123"));
        BffRawTokenContextWebFilter filter = new BffRawTokenContextWebFilter();
        WebFilterChain chain = mock(WebFilterChain.class);
        when(chain.filter(exchange)).thenReturn(Mono.deferContextual(ctx -> {
            assertThat(ctx.<String>getOrDefault(BffRawTokenContextWebFilter.CONTEXT_KEY, null))
                    .isEqualTo("bff_abc123");
            return Mono.empty();
        }));

        filter.filter(exchange, chain).block();
    }

    @Test
    void filter_leavesContextUntouched_whenNoTokenPresent() {
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/x"));
        BffRawTokenContextWebFilter filter = new BffRawTokenContextWebFilter();
        WebFilterChain chain = mock(WebFilterChain.class);
        when(chain.filter(exchange)).thenReturn(Mono.deferContextual(ctx -> {
            assertThat(ctx.hasKey(BffRawTokenContextWebFilter.CONTEXT_KEY)).isFalse();
            return Mono.empty();
        }));

        filter.filter(exchange, chain).block();
    }
}
