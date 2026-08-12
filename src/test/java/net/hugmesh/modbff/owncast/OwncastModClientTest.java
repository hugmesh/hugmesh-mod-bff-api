package net.hugmesh.modbff.owncast;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.commons.web.ApiException;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the {@link OwncastModClient} HTTP contract against owncast-bff's moderation
 * surface using a recording {@link ExchangeFunction} (the same idiom as
 * {@code AdminDomainLockClientTest}):
 * <ul>
 *   <li>hide/kill/restore POST to {@code /bff/owncast/mod/streams/{owner}/hide|ban|restore}
 *       (owncast-bff's kill verb rides its {@code /ban} path);</li>
 *   <li>a 2xx resolves to {@code ok} — the owncast effect is SYNCHRONOUS (unlike the
 *       admin-bff desired-state writers' pending-reconcile);</li>
 *   <li>a 404 (no stream for that owner in the brand) propagates as a REAL
 *       {@link ApiException} 404 — never blurred into a degraded outcome, and never a
 *       fake success.</li>
 * </ul>
 */
class OwncastModClientTest {

    /** Records outgoing requests + returns a fixed status. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        final HttpStatus status;

        Recorder(HttpStatus status) {
            this.status = status;
        }

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            return Mono.just(ClientResponse.create(status).body("").build());
        }
    }

    private static OwncastModClient client(Recorder rec) {
        return new OwncastModClient(
                WebClient.builder().baseUrl("http://owncast-bff.test").exchangeFunction(rec).build());
    }

    // ── USER-SITUATIONAL — the three verbs hit the matching effector paths ──

    @Test
    void hide_postsToHidePath_resolvesOk() {
        Recorder rec = new Recorder(HttpStatus.OK);
        StepVerifier.create(client(rec).hide("streamer-carol", "off-topic"))
                .assertNext(o -> assertThat(o.isOk()).isTrue())
                .verifyComplete();
        assertThat(rec.requests).hasSize(1);
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method()).isEqualTo(HttpMethod.POST);
        assertThat(req.url().getPath()).isEqualTo("/bff/owncast/mod/streams/streamer-carol/hide");
    }

    @Test
    void kill_postsToOwncastBffBanPath_resolvesOk() {
        Recorder rec = new Recorder(HttpStatus.OK);
        StepVerifier.create(client(rec).kill("streamer-dave", "abuse"))
                .assertNext(o -> assertThat(o.isOk()).isTrue())
                .verifyComplete();
        // The central 'kill' verb maps to owncast-bff's /ban path (its kill endpoint).
        assertThat(rec.requests.get(0).url().getPath())
                .isEqualTo("/bff/owncast/mod/streams/streamer-dave/ban");
    }

    @Test
    void restore_postsToRestorePath_resolvesOk() {
        Recorder rec = new Recorder(HttpStatus.OK);
        StepVerifier.create(client(rec).restore("streamer-dave", null))
                .assertNext(o -> assertThat(o.isOk()).isTrue())
                .verifyComplete();
        assertThat(rec.requests.get(0).url().getPath())
                .isEqualTo("/bff/owncast/mod/streams/streamer-dave/restore");
    }

    /** The optional reason travels in the JSON body (owncast-bff journals it). */
    @Test
    void hide_withReason_sendsJsonBodyWithReason() {
        Recorder rec = new Recorder(HttpStatus.OK);
        StepVerifier.create(client(rec).hide("carol", "spam stream"))
                .expectNextCount(1)
                .verifyComplete();
        String body = bodyOf(rec.requests.get(0));
        assertThat(body).contains("\"reason\":\"spam stream\"");
    }

    // ── NEGATIVE — the 404 contract answer is a REAL 404, not a blur ──────────

    @Test
    void hide_404NoStream_propagatesAsNotFound_neverASuccess() {
        Recorder rec = new Recorder(HttpStatus.NOT_FOUND);
        StepVerifier.create(client(rec).hide("ghost", null))
                .expectErrorSatisfies(e -> {
                    assertThat(e).isInstanceOf(ApiException.class);
                    assertThat(((ApiException) e).status().value()).isEqualTo(404);
                })
                .verify();
    }

    @Test
    void restore_404NoStream_propagatesAsNotFound() {
        Recorder rec = new Recorder(HttpStatus.NOT_FOUND);
        StepVerifier.create(client(rec).restore("ghost", null))
                .expectErrorSatisfies(e ->
                        assertThat(((ApiException) e).status().value()).isEqualTo(404))
                .verify();
    }

    /** Render a recorded request's body through a mock exchange so the JSON is inspectable. */
    private static String bodyOf(ClientRequest req) {
        org.springframework.mock.http.client.reactive.MockClientHttpRequest sink =
                new org.springframework.mock.http.client.reactive.MockClientHttpRequest(
                        req.method(), req.url());
        req.writeTo(sink, org.springframework.web.reactive.function.client.ExchangeStrategies
                .withDefaults()).block();
        return sink.getBodyAsString().block();
    }
}
