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
 *   <li><b>tuwunel (matrix) — WIRED admin-room command transport, dark by default</b>:
 *       disabled → {@link BlockOutcome#STUBBED} and NO HTTP; enabled without a token →
 *       {@code degraded:no-admin-token} and NO HTTP; enabled + token → the admin-room
 *       alias is resolved (GET directory, cached) and {@code !admin users deactivate
 *       @user:server} is PUT as an m.text message with a txnId. The outcome is
 *       {@code posted:<event_id>} — NEVER ok, because the 200 ACKs the post, not the
 *       bot's asynchronous effect. Any non-2xx degrades; a target that would widen the
 *       text command (whitespace/newline) is refused before any HTTP; block-instance has
 *       no tuwunel verb and degrades with NO HTTP.</li>
 * </ul>
 */
class ExternalAdminClientTest {

    /**
     * Records outgoing requests (and their serialised bodies) and replies with a
     * configurable status + a per-request JSON body (defaults to {@code {}}; the matrix
     * leg needs a {@code room_id} for the directory GET and an {@code event_id} for the
     * send PUT).
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

    // ---- tuwunel (matrix): admin-room command transport, dark by default -------------

    private static final String ADMIN_ROOM_ID = "!adm:hugmesh.net";

    /** A recorder that answers the directory lookup with a room id and the send with an event id. */
    private Recorder matrixRecorder() {
        Recorder rec = new Recorder();
        rec.reply = r -> r.url().getRawPath().contains("/directory/room/")
                ? "{\"room_id\":\"" + ADMIN_ROOM_ID + "\",\"servers\":[\"hugmesh.net\"]}"
                : "{\"event_id\":\"$evt1\"}";
        return rec;
    }

    private MatrixAdminClient matrix(Recorder rec, boolean enabled, String token) {
        return new MatrixAdminClient(web(rec), enabled, token, "hugmesh.net", "#admins:hugmesh.net");
    }

    @Test
    void matrixBlockUser_disabled_isStubbed_noHttpCall() {
        Recorder rec = matrixRecorder();
        StepVerifier.create(matrix(rec, false, "tok").blockUser("@spam:evil.example"))
                .assertNext(o -> assertThat(o.isStubbed()).isTrue())
                .verifyComplete();
        assertThat(rec.requests).isEmpty();
    }

    @Test
    void matrixBlockUser_enabled_blankToken_degrades_noHttpCall() {
        Recorder rec = matrixRecorder();
        StepVerifier.create(matrix(rec, true, " ").blockUser("@spam:evil.example"))
                .assertNext(o -> assertThat(o.result()).isEqualTo("degraded:no-admin-token"))
                .verifyComplete();
        assertThat(rec.requests).isEmpty();
    }

    @Test
    void matrixBlockUser_enabled_resolvesAdminRoom_thenPutsDeactivateCommand_postedNeverOk() {
        Recorder rec = matrixRecorder();
        StepVerifier.create(matrix(rec, true, "secret-tok").blockUser("@spam:evil.example"))
                .assertNext(o -> {
                    assertThat(o.result()).isEqualTo("posted:$evt1");
                    assertThat(o.isPosted()).isTrue();
                    assertThat(o.isOk()).isFalse(); // the 200 ACKs the post, not the bot's effect
                    assertThat(o.isStubbed()).isFalse();
                })
                .verifyComplete();
        assertThat(rec.requests).hasSize(2);
        ClientRequest lookup = rec.requests.get(0);
        assertThat(lookup.method()).isEqualTo(HttpMethod.GET);
        // the alias is percent-encoded as a path segment (# -> %23, : -> %3A)
        assertThat(lookup.url().getRawPath()).isEqualTo("/_matrix/client/v3/directory/room/%23admins%3Ahugmesh.net");
        assertThat(lookup.headers().getFirst("Authorization")).isEqualTo("Bearer secret-tok");
        ClientRequest send = rec.requests.get(1);
        assertThat(send.method()).isEqualTo(HttpMethod.PUT);
        assertThat(send.url().getRawPath())
                .startsWith("/_matrix/client/v3/rooms/%21adm%3Ahugmesh.net/send/m.room.message/modbff-");
        assertThat(send.headers().getFirst("Authorization")).isEqualTo("Bearer secret-tok");
        assertThat(rec.bodies.get(1))
                .contains("\"msgtype\":\"m.text\"")
                .contains("\"body\":\"!admin users deactivate @spam:evil.example\"");
    }

    @Test
    void matrixBlockUser_bareLocalpart_isQualifiedToServerName() {
        Recorder rec = matrixRecorder();
        StepVerifier.create(matrix(rec, true, "secret-tok").blockUser("spam"))
                .assertNext(o -> assertThat(o.isPosted()).isTrue())
                .verifyComplete();
        assertThat(rec.bodies.get(1)).contains("!admin users deactivate @spam:hugmesh.net\"");
    }

    @Test
    void matrixBlockUser_targetThatWouldWidenTheCommand_isRefused_noHttpCall() {
        // The command is ONE text line the admin bot splits into arguments: whitespace or
        // a newline in the target would smuggle extra flags/commands into the admin room.
        Recorder rec = matrixRecorder();
        MatrixAdminClient client = matrix(rec, true, "secret-tok");
        for (String bad : List.of("@spam:evil.example --no-leave-rooms",
                "@spam:evil.example\n!admin users deactivate-all", "", "@:x", "@spam:evil.example;rm")) {
            StepVerifier.create(client.blockUser(bad))
                    .assertNext(o -> assertThat(o.result()).isEqualTo("degraded:bad-target"))
                    .verifyComplete();
        }
        assertThat(rec.requests).isEmpty();
    }

    @Test
    void matrixBlockUser_secondCall_reusesCachedAdminRoom() {
        Recorder rec = matrixRecorder();
        MatrixAdminClient client = matrix(rec, true, "secret-tok");
        StepVerifier.create(client.blockUser("@a:evil.example")).expectNextCount(1).verifyComplete();
        StepVerifier.create(client.blockUser("@b:evil.example")).expectNextCount(1).verifyComplete();
        assertThat(rec.requests).hasSize(3); // GET, PUT, PUT — the alias is resolved once
        assertThat(rec.requests.get(2).method()).isEqualTo(HttpMethod.PUT);
    }

    @Test
    void matrixBlockUser_homeserverRejects_degradesHttp_neverOk_andDropsRoomCache() {
        Recorder rec = matrixRecorder();
        rec.status.set(HttpStatus.FORBIDDEN); // e.g. the token's user is not an admin-room member
        MatrixAdminClient client = matrix(rec, true, "secret-tok");
        StepVerifier.create(client.blockUser("@spam:evil.example"))
                .assertNext(o -> {
                    assertThat(o.result()).isEqualTo("degraded:http-403");
                    assertThat(o.isOk()).isFalse();
                })
                .verifyComplete();
        StepVerifier.create(client.blockUser("@spam:evil.example"))
                .assertNext(o -> assertThat(o.result()).isEqualTo("degraded:http-403"))
                .verifyComplete();
        assertThat(rec.requests).hasSize(2); // both directory GETs — nothing was cached
        assertThat(rec.requests).allSatisfy(r -> assertThat(r.method()).isEqualTo(HttpMethod.GET));
    }

    @Test
    void matrixBlockUser_sendRejectedAfterCachedRoom_dropsCache_andReResolvesNextCall() {
        // Populate the cache first (GET + PUT), then have the homeserver 403 the PUT alone
        // (the cache means no GET is issued), then recover: the next call MUST re-issue
        // the directory GET, proving degradeHttp dropped the cached room id (a recreated
        // admin room would otherwise be posted into a dead room id forever).
        Recorder rec = matrixRecorder();
        MatrixAdminClient client = matrix(rec, true, "secret-tok");
        StepVerifier.create(client.blockUser("@a:evil.example"))
                .assertNext(o -> assertThat(o.isPosted()).isTrue())
                .verifyComplete();
        assertThat(rec.requests).hasSize(2); // GET, PUT — cache populated

        rec.status.set(HttpStatus.FORBIDDEN);
        StepVerifier.create(client.blockUser("@b:evil.example"))
                .assertNext(o -> {
                    assertThat(o.result()).isEqualTo("degraded:http-403");
                    assertThat(o.isOk()).isFalse();
                })
                .verifyComplete();
        assertThat(rec.requests).hasSize(3); // PUT only — the cached room id was used
        assertThat(rec.requests.get(2).method()).isEqualTo(HttpMethod.PUT);

        rec.status.set(HttpStatus.OK);
        StepVerifier.create(client.blockUser("@c:evil.example"))
                .assertNext(o -> assertThat(o.isPosted()).isTrue())
                .verifyComplete();
        assertThat(rec.requests).hasSize(5); // GET (re-resolved), PUT
        assertThat(rec.requests.get(3).method()).isEqualTo(HttpMethod.GET);
        assertThat(rec.requests.get(3).url().getRawPath()).contains("/directory/room/");
        assertThat(rec.requests.get(4).method()).isEqualTo(HttpMethod.PUT);
    }

    @Test
    void matrixBlockUser_aliasResolvesWithoutRoomId_degrades_noSend() {
        Recorder rec = new Recorder(); // answers {} to everything — no room_id
        StepVerifier.create(matrix(rec, true, "secret-tok").blockUser("@spam:evil.example"))
                .assertNext(o -> assertThat(o.result()).isEqualTo("degraded:no-admin-room"))
                .verifyComplete();
        assertThat(rec.requests).hasSize(1);
    }

    @Test
    void matrixBlockInstance_enabled_noTuwunelVerb_degrades_noHttpCall() {
        Recorder rec = matrixRecorder();
        StepVerifier.create(matrix(rec, true, "secret-tok").blockInstance("evil.example"))
                .assertNext(o -> {
                    assertThat(o.result()).isEqualTo("degraded:no-tuwunel-verb");
                    assertThat(o.isOk()).isFalse();
                })
                .verifyComplete();
        assertThat(rec.requests).isEmpty();
    }

    @Test
    void matrixBlockInstance_disabled_isStubbed_noHttpCall() {
        Recorder rec = matrixRecorder();
        StepVerifier.create(matrix(rec, false, "secret-tok").blockInstance("evil.example"))
                .assertNext(o -> assertThat(o.result()).isEqualTo("stubbed"))
                .verifyComplete();
        assertThat(rec.requests).isEmpty();
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
