package net.hugmesh.modbff.external;

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
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.web.reactive.function.client.ExchangeStrategies;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the external homeserver admin clients (tuwunel/akkoma) against a recording
 * {@link ExchangeFunction} stub. Contract under test:
 *
 * <ul>
 *   <li><b>akkoma (mastodon) — WIRED</b>: disabled (default) → {@link BlockOutcome#STUBBED}
 *       and NO HTTP; enabled + admin token → a REAL pleroma-admin HTTP call is issued
 *       (PATCH /users/deactivate, DELETE /instances/{host}). 200 lands OK; a 404 is OK
 *       ONLY for the instance leg (Akkoma already-purged idempotency) — for the user leg
 *       404 degrades, and ANY other non-2xx (incl. a 301 redirect) degrades on both legs,
 *       never a false OK (live-grounded against the compose stack's mainline Mastodon,
 *       which 404s the missing pleroma routes and 308-redirects the plain-HTTP port);</li>
 *   <li><b>tuwunel (matrix) — instance block only, dark by default</b>: disabled →
 *       {@link BlockOutcome#STUBBED}; enabled without a token →
 *       {@code degraded:no-admin-token}; enabled + token → {@code requested:no-tuwunel-verb}
 *       (tuwunel has no runtime federation-block verb, decision 50). The client holds no
 *       HTTP client. Its former user deactivate (the admin-room
 *       {@code !admin users deactivate} transport) moved to hugmesh-admin-bff-api under
 *       decision 83b (hugmesh-mod-bff-api#23).</li>
 * </ul>
 */
class ExternalAdminClientTest {

    /**
     * Records outgoing requests (and their serialised bodies) and replies with a
     * configurable status + a per-request JSON body (defaults to {@code {}}).
     */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        final List<String> bodies = new ArrayList<>();
        final AtomicReference<HttpStatus> status = new AtomicReference<>(HttpStatus.OK);
        Function<ClientRequest, String> reply = r -> "{}";

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            MockClientHttpRequest out = new MockClientHttpRequest(request.method(), request.url());
            // read the body only AFTER writeTo has set it (defer); a bodiless GET/DELETE
            // never sets the mock body and is recorded as ""
            return request.writeTo(out, ExchangeStrategies.withDefaults())
                    .then(Mono.defer(out::getBodyAsString).onErrorReturn(""))
                    .defaultIfEmpty("")
                    .doOnNext(bodies::add)
                    .then(Mono.fromSupplier(() -> ClientResponse.create(status.get())
                            .header("Content-Type", "application/json")
                            .body(reply.apply(request)).build()));
        }
    }

    private WebClient web(Recorder rec) {
        return WebClient.builder().baseUrl("http://homeserver.test").exchangeFunction(rec).build();
    }

    // ---- tuwunel (matrix): instance block only, no HTTP client at all ---------------
    // The one-way user deactivate (admin-room "!admin users deactivate") moved to
    // hugmesh-admin-bff-api (decision 83b, hugmesh-mod-bff-api#23); its tests went with it.
    // MatrixAdminClient no longer holds a WebClient, so "no HTTP" is structural here and
    // MatrixAdminClientNoUserDeactivateTest pins that the user path stays gone.

    private MatrixAdminClient matrix(boolean enabled, String token) {
        return new MatrixAdminClient(enabled, token);
    }

    // Decision 50 (2026-09-18): recorded as a REQUEST, not a failure — nothing here can
    // attempt the effect at all, so this is deliberately NOT `degraded`.
    @Test
    void matrixBlockInstance_enabled_noTuwunelVerb_isRequested() {
        StepVerifier.create(matrix(true, "secret-tok").blockInstance("evil.example"))
                .assertNext(o -> {
                    assertThat(o.result()).isEqualTo("requested:no-tuwunel-verb");
                    assertThat(o.isRequested()).isTrue();
                    assertThat(o.isOk()).isFalse();
                })
                .verifyComplete();
    }

    @Test
    void matrixBlockInstance_disabled_isStubbed() {
        StepVerifier.create(matrix(false, "secret-tok").blockInstance("evil.example"))
                .assertNext(o -> assertThat(o.result()).isEqualTo("stubbed"))
                .verifyComplete();
    }

    @Test
    void matrixBlockInstance_enabled_blankToken_degrades() {
        StepVerifier.create(matrix(true, " ").blockInstance("evil.example"))
                .assertNext(o -> {
                    assertThat(o.result()).isEqualTo("degraded:no-admin-token");
                    assertThat(o.isOk()).isFalse();
                })
                .verifyComplete();
    }

    // ---- akkoma (mastodon): WIRED — disabled is a no-op -----------------------------

    @Test
    void mastodonBlockUser_disabled_isStubbed_noHttpCall() {
        Recorder rec = new Recorder();
        MastodonAdminClient client = new MastodonAdminClient(web(rec), false, "tok");
        StepVerifier.create(client.blockUser("@spam@evil.example"))
                .assertNext(o -> assertThat(o.isStubbed()).isTrue())
                .verifyComplete();
        assertThat(rec.requests).isEmpty();
    }

    @Test
    void mastodonBlockInstance_disabled_isStubbed_noHttpCall() {
        Recorder rec = new Recorder();
        MastodonAdminClient client = new MastodonAdminClient(web(rec), false, "tok");
        StepVerifier.create(client.blockInstance("evil.example"))
                .assertNext(o -> assertThat(o.isStubbed()).isTrue())
                .verifyComplete();
        assertThat(rec.requests).isEmpty();
    }

    // ---- akkoma (mastodon): WIRED — enabled issues the REAL pleroma-admin call ------

    @Test
    void mastodonBlockUser_enabled_issuesPatchDeactivate_withBearer_andOk() {
        Recorder rec = new Recorder();
        MastodonAdminClient client = new MastodonAdminClient(web(rec), true, "secret-tok");
        StepVerifier.create(client.blockUser("@spam@evil.example"))
                .assertNext(o -> assertThat(o.isOk()).isTrue())
                .verifyComplete();
        assertThat(rec.requests).hasSize(1);
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method()).isEqualTo(HttpMethod.PATCH);
        assertThat(req.url().getPath()).isEqualTo("/api/v1/pleroma/admin/users/deactivate");
        assertThat(req.headers().getFirst("Authorization")).isEqualTo("Bearer secret-tok");
    }

    @Test
    void mastodonBlockInstance_enabled_issuesDeleteInstance_withBearer_andOk() {
        Recorder rec = new Recorder();
        MastodonAdminClient client = new MastodonAdminClient(web(rec), true, "secret-tok");
        StepVerifier.create(client.blockInstance("evil.example"))
                .assertNext(o -> assertThat(o.isOk()).isTrue())
                .verifyComplete();
        assertThat(rec.requests).hasSize(1);
        ClientRequest req = rec.requests.get(0);
        assertThat(req.method()).isEqualTo(HttpMethod.DELETE);
        assertThat(req.url().getPath()).isEqualTo("/api/v1/pleroma/admin/instances/evil.example");
        assertThat(req.headers().getFirst("Authorization")).isEqualTo("Bearer secret-tok");
    }

    @Test
    void mastodonBlockInstance_enabled_alreadyPurged404_swallowedAsOk() {
        Recorder rec = new Recorder();
        rec.status.set(HttpStatus.NOT_FOUND); // already purged / unknown instance
        MastodonAdminClient client = new MastodonAdminClient(web(rec), true, "secret-tok");
        StepVerifier.create(client.blockInstance("gone.example"))
                .assertNext(o -> assertThat(o.isOk()).isTrue())
                .verifyComplete();
        assertThat(rec.requests).hasSize(1); // the call WAS issued, then swallowed
    }

    @Test
    void mastodonBlockUser_enabled_404_degradesNotOk() {
        // LIVE-VERIFIED (2026-07, compose stack): mainline Mastodon has NO
        // /api/v1/pleroma/* routes, so an enabled client hits a route-level 404.
        // Deactivate is an absolute set (already-applied re-issue is a natural 200),
        // so a 404 can only mean the route/user is MISSING → degraded, NEVER a false OK
        // (the pre-fix 404-swallow returned "ok" here — pinned against regression).
        Recorder rec = new Recorder();
        rec.status.set(HttpStatus.NOT_FOUND);
        MastodonAdminClient client = new MastodonAdminClient(web(rec), true, "secret-tok");
        StepVerifier.create(client.blockUser("@spam@evil.example"))
                .assertNext(o -> {
                    assertThat(o.isOk()).isFalse();
                    assertThat(o.result()).isEqualTo("degraded:http-404");
                })
                .verifyComplete();
        assertThat(rec.requests).hasSize(1);
    }

    @Test
    void mastodonBlockUser_enabled_redirect301_degradesNotOk() {
        // LIVE-VERIFIED (2026-07, compose stack): Mastodon's plain-HTTP port answers the
        // API with a force-HTTPS redirect (308 for PATCH/DELETE, 301 modeled here — any 3xx).
        // retrieve() treats 3xx as non-error by default, so the
        // pre-fix client resolved a FALSE "ok" without any admin action happening. Any
        // non-2xx must degrade, never OK.
        Recorder rec = new Recorder();
        rec.status.set(HttpStatus.MOVED_PERMANENTLY);
        MastodonAdminClient client = new MastodonAdminClient(web(rec), true, "secret-tok");
        StepVerifier.create(client.blockUser("@spam@evil.example"))
                .assertNext(o -> {
                    assertThat(o.isOk()).isFalse();
                    assertThat(o.result()).isEqualTo("degraded:http-301");
                })
                .verifyComplete();
        assertThat(rec.requests).hasSize(1);
    }

    @Test
    void mastodonBlockInstance_enabled_redirect301_degradesNotOk() {
        // The instance leg keeps ONLY the Akkoma already-purged 404 swallow; a 3xx (or any
        // other non-2xx) is not an idempotent no-op signal and must degrade (live-grounded
        // like the user-leg 301 case above).
        Recorder rec = new Recorder();
        rec.status.set(HttpStatus.MOVED_PERMANENTLY);
        MastodonAdminClient client = new MastodonAdminClient(web(rec), true, "secret-tok");
        StepVerifier.create(client.blockInstance("evil.example"))
                .assertNext(o -> {
                    assertThat(o.isOk()).isFalse();
                    assertThat(o.result()).isEqualTo("degraded:http-301");
                })
                .verifyComplete();
        assertThat(rec.requests).hasSize(1);
    }

    @Test
    void mastodonBlockUser_enabled_serverError_degradesNotOk() {
        Recorder rec = new Recorder();
        rec.status.set(HttpStatus.INTERNAL_SERVER_ERROR);
        MastodonAdminClient client = new MastodonAdminClient(web(rec), true, "secret-tok");
        StepVerifier.create(client.blockUser("@spam@evil.example"))
                .assertNext(o -> {
                    assertThat(o.isOk()).isFalse();
                    assertThat(o.result()).startsWith("degraded:");
                })
                .verifyComplete();
        assertThat(rec.requests).hasSize(1);
    }

    @Test
    void mastodonBlockUser_enabled_butBlankToken_degrades_noHttpCall() {
        Recorder rec = new Recorder();
        MastodonAdminClient client = new MastodonAdminClient(web(rec), true, "");
        StepVerifier.create(client.blockUser("@spam@evil.example"))
                .assertNext(o -> {
                    assertThat(o.isOk()).isFalse();
                    assertThat(o.result()).isEqualTo("degraded:no-admin-token");
                })
                .verifyComplete();
        assertThat(rec.requests).isEmpty(); // never an unauthenticated call
    }

    // ---- helpers + value object -----------------------------------------------------

    @Test
    void mastodonLocalpart_stripsAtAndInstance() {
        assertThat(MastodonAdminClient.localpart("@spam@evil.example")).isEqualTo("spam");
        assertThat(MastodonAdminClient.localpart("spam@evil.example")).isEqualTo("spam");
        assertThat(MastodonAdminClient.localpart("@spam")).isEqualTo("spam");
        assertThat(MastodonAdminClient.localpart("spam")).isEqualTo("spam");
    }

    @Test
    void blockOutcome_degraded_carriesReason() {
        assertThat(BlockOutcome.degraded("timeout").result()).isEqualTo("degraded:timeout");
        assertThat(BlockOutcome.OK.result()).isEqualTo("ok");
        assertThat(BlockOutcome.STUBBED.isStubbed()).isTrue();
    }

    // Decision 50/51 (2026-09-18): the two new outcome kinds are distinct from both
    // `degraded` (a failure) and `ok` (a confirmed effect) — see BlockOutcome's class
    // javadoc for why they need to stay distinguishable.
    @Test
    void blockOutcome_requested_isDistinctFromDegradedAndOk() {
        BlockOutcome requested = BlockOutcome.requested("no-tuwunel-verb");
        assertThat(requested.result()).isEqualTo("requested:no-tuwunel-verb");
        assertThat(requested.isRequested()).isTrue();
        assertThat(requested.isOk()).isFalse();
        assertThat(requested.isStubbed()).isFalse();
        assertThat(BlockOutcome.degraded("no-tuwunel-verb").isRequested()).isFalse();
    }

    @Test
    void blockOutcome_domainLocked_isNeverOk() {
        assertThat(BlockOutcome.DOMAIN_LOCKED.result()).isEqualTo("domain-locked");
        assertThat(BlockOutcome.DOMAIN_LOCKED.isDomainLocked()).isTrue();
        assertThat(BlockOutcome.DOMAIN_LOCKED.isOk()).isFalse();
    }

    // ---- A2: the deactivate nickname must be FOLDED to the provisioned akkoma form ----

    @Test
    void mastodonLocalpart_foldsToTheProvisionedAkkomaNickname() {
        // Provisioning mints the akkoma account under mastodonLocalpart (only [a-z0-9_], 30-cap).
        // A moderation deactivate targeting the raw local part would 404 the wrong nickname, so
        // block-user must apply the SAME fold. dotted / hyphenated / uppercase all fold.
        assertThat(MastodonAdminClient.localpart("alice.smith")).isEqualTo("alice_smith");
        assertThat(MastodonAdminClient.localpart("@alice.smith@evil.example")).isEqualTo("alice_smith");
        assertThat(MastodonAdminClient.localpart("John-Doe")).isEqualTo("john_doe");
        // Idempotent: an already-folded @user@instance nickname is unchanged.
        assertThat(MastodonAdminClient.localpart("@alice_smith@evil.example")).isEqualTo("alice_smith");
        assertThat(MastodonAdminClient.localpart("bob")).isEqualTo("bob");
        // 30-char cap + all-disallowed → "user" fallback (mirrors ServiceTokenBroker.mastodonLocalpart).
        assertThat(MastodonAdminClient.localpart("a".repeat(40))).hasSize(30);
        assertThat(MastodonAdminClient.localpart("...")).isEqualTo("user");
    }
}
