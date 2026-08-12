package net.hugmesh.modbff.federation;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the {@link FederationApiClient} issues the documented federation-api
 * calls (paths, methods, body) against a recording {@link ExchangeFunction} stub —
 * no live federation-api needed. The endpoint shapes are matched field-for-field to
 * hugmesh-federation-api ModerationController / FederationController.
 */
class FederationApiClientTest {

    /** Records every outgoing request and replies with canned JSON per path. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            String path = request.url().getPath();
            String body;
            if (path.endsWith("/manifest")) {
                body = "{\"generatedAt\":\"2026-06-06T00:00:00Z\",\"remotes\":["
                        + "{\"slug\":\"mod-tools\",\"displayName\":\"Mod Tools\",\"kind\":\"remote-shell\","
                        + "\"remoteEntryUrl\":\"https://cdn/remoteEntry.js\",\"exposedModule\":\"./Mod\","
                        + "\"version\":\"1.0.0\",\"contentHash\":\"abc\",\"visibility\":\"internal\",\"metadata\":\"{}\"}]}";
            } else if (path.endsWith("/refer")) {
                body = "{\"id\":7,\"requester\":\"u\",\"kind\":\"user-removal\",\"target\":\"@x:y\","
                        + "\"reason\":\"r\",\"status\":\"referred\",\"modReferrer\":\"mod:bob\",\"ts\":\"2026-06-06T00:00:00Z\"}";
            } else if (path.endsWith("/moderation") && request.method().name().equals("POST")) {
                body = "{\"id\":8,\"requester\":\"mod:bob\",\"kind\":\"instance-block\",\"target\":\"evil.example\","
                        + "\"reason\":\"spam\",\"status\":\"recommended\",\"ts\":\"2026-06-06T00:00:00Z\"}";
            } else if (path.endsWith("/resolve")) {
                body = "{\"id\":9,\"reporter\":\"@system\",\"subject\":\"u:carol\",\"surface\":\"profile-avatar\","
                        + "\"disposition\":\"flagged\",\"classification\":\"nsfw\",\"confidence\":0.91,\"policyHit\":true,"
                        + "\"perceptualHash\":\"ph\",\"status\":\"actioned\",\"reviewer\":\"mod:bob\","
                        + "\"ts\":\"2026-06-06T00:00:00Z\",\"domain\":\"default\"}";
            } else if (path.endsWith("/findings")) {
                body = "[{\"id\":9,\"reporter\":\"@system\",\"subject\":\"u:carol\",\"surface\":\"profile-avatar\","
                        + "\"disposition\":\"flagged\",\"classification\":\"nsfw\",\"confidence\":0.91,\"policyHit\":true,"
                        + "\"perceptualHash\":\"ph\",\"status\":\"held\",\"reviewer\":null,"
                        + "\"ts\":\"2026-06-06T00:00:00Z\",\"domain\":\"default\"}]";
            } else { // GET /moderation list
                body = "[{\"id\":1,\"requester\":\"u\",\"kind\":\"instance-block\",\"target\":\"evil.example\","
                        + "\"reason\":\"spam\",\"status\":\"recommended\",\"ts\":\"2026-06-06T00:00:00Z\"}]";
            }
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", "application/json")
                    .body(body).build());
        }

        ClientRequest last() { return requests.get(requests.size() - 1); }
    }

    private FederationApiClient clientFor(Recorder rec) {
        WebClient web = WebClient.builder()
                .baseUrl("http://federation-api.test")
                .exchangeFunction(rec).build();
        return new FederationApiClient(web);
    }

    @Test
    void listModeration_getsModerationPath_andDeserialises() {
        Recorder rec = new Recorder();
        StepVerifier.create(clientFor(rec).listModeration(null))
                .assertNext(r -> {
                    assertThat(r.id()).isEqualTo(1L);
                    assertThat(r.kind()).isEqualTo("instance-block");
                    assertThat(r.status()).isEqualTo("recommended");
                })
                .verifyComplete();
        assertThat(rec.last().url().getPath()).isEqualTo("/api/federation/moderation");
        assertThat(rec.last().method().name()).isEqualTo("GET");
    }

    @Test
    void listModeration_withStatus_addsQueryParam() {
        Recorder rec = new Recorder();
        clientFor(rec).listModeration("referred").collectList().block();
        assertThat(rec.last().url().getQuery()).isEqualTo("status=referred");
    }

    @Test
    void submitModeration_postsBodyToModerationPath() {
        Recorder rec = new Recorder();
        StepVerifier.create(clientFor(rec).submitModeration(
                        new SubmitModerationRequest("instance-block", "evil.example", "spam")))
                .assertNext(r -> {
                    assertThat(r.id()).isEqualTo(8L);
                    assertThat(r.status()).isEqualTo("recommended");
                })
                .verifyComplete();
        assertThat(rec.last().url().getPath()).isEqualTo("/api/federation/moderation");
        assertThat(rec.last().method().name()).isEqualTo("POST");
    }

    @Test
    void referModeration_postsToReferPath() {
        Recorder rec = new Recorder();
        StepVerifier.create(clientFor(rec).referModeration(7L))
                .assertNext(r -> assertThat(r.status()).isEqualTo("referred"))
                .verifyComplete();
        assertThat(rec.last().url().getPath()).isEqualTo("/api/federation/moderation/7/refer");
        assertThat(rec.last().method().name()).isEqualTo("POST");
    }

    @Test
    void manifest_getsManifestPath_andDeserialisesRemotes() {
        Recorder rec = new Recorder();
        StepVerifier.create(clientFor(rec).manifest())
                .assertNext(m -> {
                    assertThat(m.generatedAt()).isEqualTo("2026-06-06T00:00:00Z");
                    assertThat(m.remotes()).hasSize(1);
                    assertThat(m.remotes().get(0).slug()).isEqualTo("mod-tools");
                    assertThat(m.remotes().get(0).visibility()).isEqualTo("internal");
                })
                .verifyComplete();
        assertThat(rec.last().url().getPath()).isEqualTo("/api/federation/manifest");
    }

    @Test
    void listFindings_getsFindingsPath_andDeserialises() {
        Recorder rec = new Recorder();
        StepVerifier.create(clientFor(rec).listFindings(null))
                .assertNext(f -> {
                    assertThat(f.id()).isEqualTo(9L);
                    assertThat(f.reporter()).isEqualTo("@system");
                    assertThat(f.subject()).isEqualTo("u:carol");
                    assertThat(f.surface()).isEqualTo("profile-avatar");
                    assertThat(f.disposition()).isEqualTo("flagged");
                    assertThat(f.status()).isEqualTo("held");
                    assertThat(f.confidence()).isEqualTo(0.91);
                    assertThat(f.policyHit()).isTrue();
                })
                .verifyComplete();
        assertThat(rec.last().url().getPath()).isEqualTo("/api/federation/findings");
        assertThat(rec.last().method().name()).isEqualTo("GET");
    }

    @Test
    void listFindings_withStatus_addsQueryParam() {
        Recorder rec = new Recorder();
        clientFor(rec).listFindings("held").collectList().block();
        assertThat(rec.last().url().getQuery()).isEqualTo("status=held");
    }

    @Test
    void resolveFinding_postsToResolvePath_withActionedQuery() {
        Recorder rec = new Recorder();
        StepVerifier.create(clientFor(rec).resolveFinding(9L, true))
                .assertNext(f -> {
                    assertThat(f.id()).isEqualTo(9L);
                    assertThat(f.status()).isEqualTo("actioned");
                    assertThat(f.reviewer()).isEqualTo("mod:bob");
                })
                .verifyComplete();
        assertThat(rec.last().url().getPath()).isEqualTo("/api/federation/findings/9/resolve");
        assertThat(rec.last().url().getQuery()).isEqualTo("actioned=true");
        assertThat(rec.last().method().name()).isEqualTo("POST");
    }

    @Test
    void resolveFinding_dismiss_addsActionedFalseQuery() {
        Recorder rec = new Recorder();
        clientFor(rec).resolveFinding(9L, false).block();
        assertThat(rec.last().url().getQuery()).isEqualTo("actioned=false");
    }
}
