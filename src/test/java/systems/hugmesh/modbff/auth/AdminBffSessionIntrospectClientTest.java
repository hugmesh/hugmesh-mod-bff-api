package systems.hugmesh.modbff.auth;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the {@link AdminBffSessionIntrospectClient} HTTP contract against admin-bff's
 * {@code GET /bff/internal/session/introspect} endpoint using a recording
 * {@link ExchangeFunction} — same idiom as {@code AdminDomainLockClientTest}.
 */
class AdminBffSessionIntrospectClientTest {

    /** Records outgoing requests and replays a canned response. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        ClientResponse next;

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            return Mono.just(next);
        }
    }

    private static WebClient web(Recorder rec) {
        return WebClient.builder().baseUrl("http://admin-bff.test").exchangeFunction(rec).build();
    }

    @Test
    void introspect_getsTheIntrospectEndpoint_withBearerToken() {
        Recorder rec = new Recorder();
        rec.next = ClientResponse.create(HttpStatus.OK)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .body("""
                        {"id":"casdoor:mod1","provider":"casdoor","roles":["mod"],
                         "registrationComplete":true,"status":"active","mfaSatisfied":false}
                        """)
                .build();
        AdminBffSessionIntrospectClient client = new AdminBffSessionIntrospectClient(web(rec));

        StepVerifier.create(client.introspect("bff_abc123"))
                .assertNext(intro -> {
                    assertThat(intro.id()).isEqualTo("casdoor:mod1");
                    assertThat(intro.roles()).containsExactly("mod");
                    assertThat(intro.registrationComplete()).isTrue();
                    assertThat(intro.status()).isEqualTo("active");
                    assertThat(intro.mfaSatisfied()).isFalse();
                })
                .verifyComplete();

        assertThat(rec.requests).hasSize(1);
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method()).isEqualTo(HttpMethod.GET);
        assertThat(req.url().getPath()).isEqualTo("/bff/internal/session/introspect");
        assertThat(req.headers().getFirst(HttpHeaders.AUTHORIZATION)).isEqualTo("Bearer bff_abc123");
    }

    @Test
    void unknownSession_401Propagates_asWebClientResponseExceptionUnauthorized() {
        Recorder rec = new Recorder();
        rec.next = ClientResponse.create(HttpStatus.UNAUTHORIZED).body("").build();
        AdminBffSessionIntrospectClient client = new AdminBffSessionIntrospectClient(web(rec));

        StepVerifier.create(client.introspect("bff_expired"))
                .expectError(WebClientResponseException.Unauthorized.class)
                .verify();
    }

    @Test
    void backendError_5xxPropagates() {
        Recorder rec = new Recorder();
        rec.next = ClientResponse.create(HttpStatus.INTERNAL_SERVER_ERROR).body("").build();
        AdminBffSessionIntrospectClient client = new AdminBffSessionIntrospectClient(web(rec));

        StepVerifier.create(client.introspect("bff_whatever"))
                .expectError(WebClientResponseException.InternalServerError.class)
                .verify();
    }

    @Test
    void unknownResponseFields_areIgnored() {
        // Forward-compat: admin-bff may add fields to the introspect body later.
        Recorder rec = new Recorder();
        rec.next = ClientResponse.create(HttpStatus.OK)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .body("""
                        {"id":"casdoor:u1","provider":"casdoor","roles":[],
                         "registrationComplete":true,"status":"active","mfaSatisfied":true,
                         "somethingNewAndUnexpected":"ignored-please"}
                        """)
                .build();
        AdminBffSessionIntrospectClient client = new AdminBffSessionIntrospectClient(web(rec));

        StepVerifier.create(client.introspect("bff_x"))
                .assertNext(intro -> assertThat(intro.mfaSatisfied()).isTrue())
                .verifyComplete();
    }
}
