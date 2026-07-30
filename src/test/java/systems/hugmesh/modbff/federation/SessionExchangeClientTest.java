package systems.hugmesh.modbff.federation;

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
 * Pins the {@link SessionExchangeClient} HTTP contract against admin-bff's
 * {@code POST /bff/internal/session/exchange} endpoint — same idiom as {@code
 * AdminBffSessionIntrospectClientTest}.
 */
class SessionExchangeClientTest {

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
    void exchange_postsTheExchangeEndpoint_withTheRawTokenInTheBody() {
        Recorder rec = new Recorder();
        rec.next = ClientResponse.create(HttpStatus.OK)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .body("{\"bearer\":\"real-casdoor-jwt\"}")
                .build();
        SessionExchangeClient client = new SessionExchangeClient(web(rec));

        StepVerifier.create(client.exchange("bff_abc123"))
                .expectNext("real-casdoor-jwt")
                .verifyComplete();

        assertThat(rec.requests).hasSize(1);
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method()).isEqualTo(HttpMethod.POST);
        assertThat(req.url().getPath()).isEqualTo("/bff/internal/session/exchange");
        // The raw token travels in the JSON BODY (not a header) — matches
        // InternalAccountController.ExchangeRequest(String token), NOT the introspect
        // endpoint's Authorization-header convention.
        assertThat(req.headers().getFirst(HttpHeaders.AUTHORIZATION)).isNull();
    }

    @Test
    void blankBearerField_completesEmpty() {
        Recorder rec = new Recorder();
        rec.next = ClientResponse.create(HttpStatus.OK)
                .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .body("{\"bearer\":\"\"}")
                .build();
        SessionExchangeClient client = new SessionExchangeClient(web(rec));

        StepVerifier.create(client.exchange("bff_abc123")).verifyComplete();
    }

    @Test
    void custodyDisabled_503Propagates() {
        Recorder rec = new Recorder();
        rec.next = ClientResponse.create(HttpStatus.SERVICE_UNAVAILABLE).body("custody disabled").build();
        SessionExchangeClient client = new SessionExchangeClient(web(rec));

        StepVerifier.create(client.exchange("bff_abc123"))
                .expectError(WebClientResponseException.ServiceUnavailable.class)
                .verify();
    }

    @Test
    void unknownSession_404Propagates() {
        Recorder rec = new Recorder();
        rec.next = ClientResponse.create(HttpStatus.NOT_FOUND).body("session not found").build();
        SessionExchangeClient client = new SessionExchangeClient(web(rec));

        StepVerifier.create(client.exchange("bff_gone"))
                .expectError(WebClientResponseException.NotFound.class)
                .verify();
    }

    @Test
    void suspendedAccount_403Propagates() {
        Recorder rec = new Recorder();
        rec.next = ClientResponse.create(HttpStatus.FORBIDDEN).body("account-suspended").build();
        SessionExchangeClient client = new SessionExchangeClient(web(rec));

        StepVerifier.create(client.exchange("bff_banned"))
                .expectError(WebClientResponseException.Forbidden.class)
                .verify();
    }
}
