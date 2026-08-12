package net.hugmesh.modbff.admin;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
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
 * Pins the {@link AdminDomainLockClient} HTTP contract against admin-bff's domain-lock
 * surface using a recording {@link ExchangeFunction}: a LOCK is a
 * {@code POST /bff/admin/domain-lock/{platform}/{user}}, an UNLOCK is the matching
 * {@code DELETE}, and BOTH resolve to {@link SuspensionOutcome#PENDING} (the
 * desired-state was written; the reconcile loop applies it). This is the ADD-semantics
 * sibling of {@code AdminSuspensionClient} — a SEPARATE admin-bff table, never
 * overloading access_suspension.
 */
class AdminDomainLockClientTest {

    /** Records outgoing requests + returns 200 so the client resolves to PENDING. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            return Mono.just(ClientResponse.create(HttpStatus.OK).body("").build());
        }
    }

    private WebClient web(Recorder rec) {
        return WebClient.builder().baseUrl("http://admin-bff.test").exchangeFunction(rec).build();
    }

    @Test
    void lock_postsToDomainLockEndpoint_returnsPending() {
        Recorder rec = new Recorder();
        AdminDomainLockClient client = new AdminDomainLockClient(web(rec));
        StepVerifier.create(client.lock("matrix", "alice", "abuse"))
                .assertNext(o -> assertThat(o.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();
        assertThat(rec.requests).hasSize(1);
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method()).isEqualTo(HttpMethod.POST);
        assertThat(req.url().getPath()).isEqualTo("/bff/admin/domain-lock/matrix/alice");
    }

    @Test
    void unlock_deletesDomainLockEndpoint_returnsPending() {
        Recorder rec = new Recorder();
        AdminDomainLockClient client = new AdminDomainLockClient(web(rec));
        StepVerifier.create(client.unlock("mastodon", "alice"))
                .assertNext(o -> assertThat(o.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();
        assertThat(rec.requests).hasSize(1);
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method()).isEqualTo(HttpMethod.DELETE);
        assertThat(req.url().getPath()).isEqualTo("/bff/admin/domain-lock/mastodon/alice");
    }
}
