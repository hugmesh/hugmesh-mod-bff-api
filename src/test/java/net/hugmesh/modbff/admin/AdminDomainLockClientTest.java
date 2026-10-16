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
 * {@code POST /bff/admin/domain-lock/{role}/{user}}, an UNLOCK is the matching
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
        StepVerifier.create(client.lock(AdminDomainLockClient.ROLE_MATRIX_DOMAINLOCKED, "alice", "abuse"))
                .assertNext(o -> assertThat(o.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();
        assertThat(rec.requests).hasSize(1);
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method()).isEqualTo(HttpMethod.POST);
        assertThat(req.url().getPath()).isEqualTo("/bff/admin/domain-lock/ROLE_MATRIX_DOMAINLOCKED/alice");
    }

    @Test
    void unlock_deletesDomainLockEndpoint_returnsPending() {
        Recorder rec = new Recorder();
        AdminDomainLockClient client = new AdminDomainLockClient(web(rec));
        StepVerifier.create(client.unlock(AdminDomainLockClient.ROLE_MASTODON_DOMAINLOCKED, "alice"))
                .assertNext(o -> assertThat(o.state()).isEqualTo("pending-reconcile"))
                .verifyComplete();
        assertThat(rec.requests).hasSize(1);
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method()).isEqualTo(HttpMethod.DELETE);
        assertThat(req.url().getPath()).isEqualTo("/bff/admin/domain-lock/ROLE_MASTODON_DOMAINLOCKED/alice");
    }

    /**
     * The path segment admin-bff accepts: its {@code AdminController} validates the
     * {@code {role}} variable with {@code @Pattern(regexp =
     * "ROLE_MATRIX_DOMAINLOCKED|ROLE_MASTODON_DOMAINLOCKED")} and answers any other value
     * (for example the platform name {@code matrix}) with 400 (hugmesh-mod-bff-api#26).
     * Copied verbatim from admin-bff so a drift on either side shows up here.
     */
    static final String ADMIN_BFF_ROLE_PATTERN = "ROLE_MATRIX_DOMAINLOCKED|ROLE_MASTODON_DOMAINLOCKED";

    private static String roleSegment(ClientRequest req) {
        String[] parts = req.url().getRawPath().split("/");
        // "", "bff", "admin", "domain-lock", <role>, <user>
        assertThat(parts).hasSize(6);
        assertThat(parts[3]).isEqualTo("domain-lock");
        return parts[4];
    }

    @Test
    void lockAndUnlock_sendARoleAdminBffAccepts_neverAPlatformName() {
        for (String role : List.of(AdminDomainLockClient.ROLE_MATRIX_DOMAINLOCKED,
                AdminDomainLockClient.ROLE_MASTODON_DOMAINLOCKED)) {
            Recorder rec = new Recorder();
            AdminDomainLockClient client = new AdminDomainLockClient(web(rec));
            StepVerifier.create(client.lock(role, "alice", null)).expectNextCount(1).verifyComplete();
            StepVerifier.create(client.unlock(role, "alice")).expectNextCount(1).verifyComplete();
            assertThat(rec.requests).hasSize(2);
            for (ClientRequest req : rec.requests) {
                assertThat(roleSegment(req)).isEqualTo(role).matches(ADMIN_BFF_ROLE_PATTERN);
                assertThat(roleSegment(req)).isNotIn("matrix", "mastodon");
            }
        }
    }

    @Test
    void user_isPathEncoded_andRoleStaysTheSecondToLastSegment() {
        Recorder rec = new Recorder();
        AdminDomainLockClient client = new AdminDomainLockClient(web(rec));
        StepVerifier.create(client.lock(AdminDomainLockClient.ROLE_MATRIX_DOMAINLOCKED, "frank@gmail.com", null))
                .expectNextCount(1).verifyComplete();
        assertThat(rec.requests.get(0).url().getRawPath())
                .isEqualTo("/bff/admin/domain-lock/ROLE_MATRIX_DOMAINLOCKED/frank%40gmail.com");
    }
}
