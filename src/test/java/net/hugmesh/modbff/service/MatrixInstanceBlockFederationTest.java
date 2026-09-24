package net.hugmesh.modbff.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InOrder;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.modbff.admin.AdminDomainLockClient;
import net.hugmesh.modbff.admin.AdminSuspensionClient;
import net.hugmesh.modbff.admin.CasdoorRoleClient;
import net.hugmesh.modbff.admin.SuspensionOutcome;
import net.hugmesh.modbff.audit.ModAction;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.external.BlockOutcome;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.external.MatrixAdminClient;
import net.hugmesh.modbff.federation.FederationApiClient;
import net.hugmesh.modbff.federation.ModerationRequestDto;
import net.hugmesh.modbff.federation.SubmitModerationRequest;
import net.hugmesh.modbff.owncast.OwncastModClient;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * Pins operator decisions 84a-d (hugmesh-generator#347, answered 2026-09-23;
 * hugmesh-federation-api#7, hugmesh-generator#564): a Matrix INSTANCE block routes into
 * federation-api's {@code moderation_requests} submit → refer → decide trail.
 * <ul>
 *   <li>84a = B — look for an OPEN ({@code recommended}/{@code referred}) instance-block
 *       row for the same domain first, and file only when there is none;</li>
 *   <li>84c = A — a fresh filing is submit THEN refer; an open {@code recommended} row
 *       (e.g. a user's own recommendation) is referred, not duplicated;</li>
 *   <li>84b = A — the moderator's own token is forwarded; a 401 does not fail the block,
 *       the mod_action row is still recorded and the body says {@code unauthorized};</li>
 *   <li>84d = A — the {@code moderation_requests} id is a dedicated response field.</li>
 * </ul>
 * On origin/main before this change the block path called federation-api nowhere, so
 * every federation interaction / id assertion below is RED there.
 */
class MatrixInstanceBlockFederationTest {

    private static final String DOMAIN = "evil.example";

    AdminSuspensionClient suspensions;
    AdminDomainLockClient domainLocks;
    CasdoorRoleClient roles;
    ModActionRepository audit;
    MatrixAdminClient matrix;
    MastodonAdminClient mastodon;
    OwncastModClient owncast;
    FederationApiClient federation;
    ModService service;

    private static Authentication mod() {
        return new UsernamePasswordAuthenticationToken("mod:bob", "n/a",
                AuthorityUtils.createAuthorityList("ROLE_MOD", "ROLE_MATRIX", "ROLE_MASTODON", "DOMAIN_default"));
    }

    private static ModAction row(String action) {
        return new ModAction("id-1", "mod:bob", action, "matrix", DOMAIN, "abuse", "requested:no-tuwunel-verb",
                LocalDateTime.parse("2026-09-23T00:00:00"), null, null, null, null);
    }

    private static ModerationRequestDto req(long id, String kind, String target, String status) {
        return new ModerationRequestDto(id, "u:someone", kind, target, "spam", status,
                "referred".equals(status) ? "mod:alice" : null, null, Instant.parse("2026-09-23T00:00:00Z"));
    }

    private ModService serviceWith(FederationApiClient client) {
        return new ModService(suspensions, domainLocks, roles, audit, matrix, mastodon, owncast, client);
    }

    @BeforeEach
    void setUp() {
        suspensions = mock(AdminSuspensionClient.class);
        domainLocks = mock(AdminDomainLockClient.class);
        roles = mock(CasdoorRoleClient.class);
        audit = mock(ModActionRepository.class);
        matrix = mock(MatrixAdminClient.class);
        mastodon = mock(MastodonAdminClient.class);
        owncast = mock(OwncastModClient.class);
        federation = mock(FederationApiClient.class);
        service = serviceWith(federation);

        when(roles.isPrivileged(anyString(), any())).thenReturn(Mono.just(false));
        when(roles.belongsToDomain(anyString(), any())).thenReturn(Mono.just(true));
        when(domainLocks.lock(anyString(), anyString(), any())).thenReturn(Mono.just(SuspensionOutcome.PENDING));
        when(audit.record(anyString(), anyString(), anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(row("matrix.block-instance")));
        when(matrix.blockInstance(anyString())).thenReturn(Mono.just(BlockOutcome.requested("no-tuwunel-verb")));
        when(mastodon.blockInstance(anyString())).thenReturn(Mono.just(BlockOutcome.STUBBED));
        when(federation.listModeration(anyString())).thenReturn(Flux.empty());
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> fed(ModService.BlockResult r) {
        return (Map<String, Object>) r.body().get("federation");
    }

    // ── 84a: an open row for the same domain means NO new submit, and its id is used ──

    @Test
    void openReferredRow_isReused_noSubmitNoRefer() {
        when(federation.listModeration("referred"))
                .thenReturn(Flux.just(req(41, "instance-block", " Evil.Example. ", "referred")));
        when(federation.listModeration("recommended"))
                .thenReturn(Flux.just(req(40, "instance-block", DOMAIN, "recommended")));

        StepVerifier.create(service.block("matrix", "instance", DOMAIN, "abuse", mod()))
                .assertNext(r -> {
                    assertThat(r.body().get("moderationRequestId")).isEqualTo(41L);
                    assertThat(fed(r)).containsEntry("status", "existing")
                            .containsEntry("moderationRequestId", 41L)
                            .containsEntry("requestStatus", "referred");
                    assertThat(r.body().get("note").toString()).contains("#41");
                })
                .verifyComplete();
        verify(federation, never()).submitModeration(any());
        verify(federation, never()).referModeration(anyLong());
    }

    @Test
    void usersOwnOpenRecommendation_countsAsOpen_referredNotDuplicated() {
        // A plain user's /recommend-instance-block row (requester = that user) is OPEN.
        when(federation.listModeration("recommended"))
                .thenReturn(Flux.just(req(17, "instance-block", DOMAIN, "recommended")));
        when(federation.referModeration(17L))
                .thenReturn(Mono.just(req(17, "instance-block", DOMAIN, "referred")));

        StepVerifier.create(service.block("matrix", "instance", DOMAIN, "abuse", mod()))
                .assertNext(r -> {
                    assertThat(r.body().get("moderationRequestId")).isEqualTo(17L);
                    assertThat(fed(r)).containsEntry("status", "referred-existing")
                            .containsEntry("requestStatus", "referred");
                })
                .verifyComplete();
        verify(federation, never()).submitModeration(any());
        verify(federation).referModeration(17L);
    }

    // ── 84c: first block = submit THEN refer; unrelated rows never count as open ──

    @Test
    void noOpenRow_submitsThenRefers_inThatOrder() {
        // None of these is an open instance-block for THIS domain.
        when(federation.listModeration("recommended")).thenReturn(Flux.just(
                req(1, "instance-block", "other.example", "recommended"),
                req(2, "user-removal", DOMAIN, "recommended"),
                req(3, "instance-block", "sub." + DOMAIN, "recommended")));
        when(federation.listModeration("referred")).thenReturn(Flux.just(
                req(4, "instance-block", DOMAIN + ".evil", "referred")));
        when(federation.submitModeration(any()))
                .thenReturn(Mono.just(req(99, "instance-block", DOMAIN, "recommended")));
        when(federation.referModeration(99L))
                .thenReturn(Mono.just(req(99, "instance-block", DOMAIN, "referred")));

        StepVerifier.create(service.block("matrix", "instance", DOMAIN, "abuse", mod()))
                .assertNext(r -> {
                    assertThat(r.body().get("moderationRequestId")).isEqualTo(99L);
                    assertThat(fed(r)).containsEntry("status", "filed")
                            .containsEntry("requestStatus", "referred");
                    assertThat(r.body().get("state")).isEqualTo("pending-reconcile");
                })
                .verifyComplete();

        InOrder order = inOrder(audit, federation);
        // The mod_action row is written BEFORE any federation call (84b: it survives any failure).
        order.verify(audit).record(anyString(), anyString(), anyString(), anyString(), any(), anyString(), anyString());
        order.verify(federation).submitModeration(new SubmitModerationRequest("instance-block", DOMAIN, "abuse"));
        order.verify(federation).referModeration(99L);
        verify(federation).listModeration("recommended");
        verify(federation).listModeration("referred");
    }

    @Test
    void closedRowsDoNotCountAsOpen() {
        // A server that ignored ?status= must not make an approved/denied row look open.
        when(federation.listModeration("recommended"))
                .thenReturn(Flux.just(req(5, "instance-block", DOMAIN, "denied")));
        when(federation.listModeration("referred"))
                .thenReturn(Flux.just(req(6, "instance-block", DOMAIN, "approved")));
        when(federation.submitModeration(any()))
                .thenReturn(Mono.just(req(7, "instance-block", DOMAIN, "recommended")));
        when(federation.referModeration(7L)).thenReturn(Mono.just(req(7, "instance-block", DOMAIN, "referred")));

        StepVerifier.create(service.block("matrix", "instance", DOMAIN, "abuse", mod()))
                .assertNext(r -> assertThat(r.body().get("moderationRequestId")).isEqualTo(7L))
                .verifyComplete();
        verify(federation).submitModeration(any());
    }

    // ── 84b: the moderator's token is refused → block still recorded, body says so ──

    /** A REAL FederationApiClient over a WebClient whose every exchange is a 401 — the
     *  exact WebClientResponseException.Unauthorized a native-login moderator with no
     *  forwarded bearer would provoke. */
    @Test
    void federation401_blockStillRecorded_bodyCarriesUnauthorized() {
        List<ClientRequest> seen = new ArrayList<>();
        WebClient unauthorized = WebClient.builder()
                .exchangeFunction(request -> {
                    seen.add(request);
                    return Mono.just(ClientResponse.create(HttpStatus.UNAUTHORIZED).build());
                })
                .build();
        ModService svc = serviceWith(new FederationApiClient(unauthorized));

        StepVerifier.create(svc.block("matrix", "instance", DOMAIN, "abuse", mod()))
                .assertNext(r -> {
                    assertThat(r.action()).isNotNull();
                    assertThat(r.body().get("state")).isEqualTo("pending-reconcile");
                    assertThat(r.body()).containsKey("moderationRequestId");
                    assertThat(r.body().get("moderationRequestId")).isNull();
                    assertThat(fed(r)).containsEntry("status", "unauthorized")
                            .containsEntry("httpStatus", 401);
                    assertThat(r.body().get("note").toString()).contains("401").contains("NOT filed");
                })
                .verifyComplete();
        verify(audit).record(anyString(), anyString(), anyString(), anyString(), any(), anyString(), anyString());
        assertThat(seen).isNotEmpty().allMatch(req -> "GET".equals(req.method().name()));
    }

    @Test
    void refer401AfterSubmit_keepsTheNewId_marksItStillRecommended() {
        when(federation.submitModeration(any()))
                .thenReturn(Mono.just(req(55, "instance-block", DOMAIN, "recommended")));
        when(federation.referModeration(55L)).thenReturn(Mono.error(WebClientResponseException.create(
                401, "Unauthorized", null, "".getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8)));

        StepVerifier.create(service.block("matrix", "instance", DOMAIN, "abuse", mod()))
                .assertNext(r -> {
                    assertThat(r.body().get("moderationRequestId")).isEqualTo(55L);
                    assertThat(fed(r)).containsEntry("status", "unauthorized")
                            .containsEntry("requestStatus", "recommended");
                })
                .verifyComplete();
    }

    @Test
    void federation5xx_isError_notUnauthorized_andNeverFailsTheBlock() {
        when(federation.listModeration("referred")).thenReturn(Flux.error(WebClientResponseException.create(
                503, "Unavailable", null, "".getBytes(StandardCharsets.UTF_8), StandardCharsets.UTF_8)));

        StepVerifier.create(service.block("matrix", "instance", DOMAIN, "abuse", mod()))
                .assertNext(r -> {
                    assertThat(fed(r)).containsEntry("status", "error").containsEntry("httpStatus", 503);
                    assertThat(r.body().get("moderationRequestId")).isNull();
                })
                .verifyComplete();
        verify(federation, never()).submitModeration(any());
    }

    @Test
    void hungFederationApi_timesOut_blockStillAnswers() {
        when(federation.listModeration(anyString())).thenReturn(Flux.never());

        StepVerifier.withVirtualTime(() -> service.block("matrix", "instance", DOMAIN, "abuse", mod()))
                .thenAwait(ModService.FEDERATION_CALL_TIMEOUT.plus(Duration.ofSeconds(1)))
                .assertNext(r -> assertThat(fed(r)).containsEntry("status", "error"))
                .expectComplete()
                // Wall-clock bound so a removed timeout FAILS this test instead of hanging it.
                .verify(Duration.ofSeconds(5));
    }

    // ── 84d: the dedicated id field; only the Matrix INSTANCE leg files anything ──

    @Test
    void otherBlocks_carryANullIdField_andNeverCallFederationApi() {
        StepVerifier.create(service.block("mastodon", "instance", DOMAIN, "abuse", mod()))
                .assertNext(r -> {
                    assertThat(r.body()).containsKey("moderationRequestId").doesNotContainKey("federation");
                    assertThat(r.body().get("moderationRequestId")).isNull();
                })
                .verifyComplete();
        StepVerifier.create(service.block("matrix", "user", "@spam:" + DOMAIN, "abuse", mod()))
                .assertNext(r -> assertThat(r.body()).doesNotContainKey("federation"))
                .verifyComplete();
        verifyNoInteractions(federation);
    }

    @Test
    void stubbedMatrixInstanceBlock_noteDoesNotClaimLocalOnly_whenFiled() {
        when(matrix.blockInstance(anyString())).thenReturn(Mono.just(BlockOutcome.STUBBED));
        when(federation.submitModeration(any()))
                .thenReturn(Mono.just(req(12, "instance-block", DOMAIN, "recommended")));
        when(federation.referModeration(12L)).thenReturn(Mono.just(req(12, "instance-block", DOMAIN, "referred")));

        StepVerifier.create(service.block("matrix", "instance", DOMAIN, "abuse", mod()))
                .assertNext(r -> {
                    assertThat(r.body().get("state")).isEqualTo("pending-reconcile");
                    assertThat(r.body().get("moderationRequestId")).isEqualTo(12L);
                    assertThat(r.body().get("note").toString())
                            .contains("STUBBED").contains("#12").doesNotContain("local audit table only");
                })
                .verifyComplete();
    }

    @Test
    void domainNormalisation_trimsLowercasesAndDropsOneRootDot() {
        assertThat(ModService.normaliseDomain(" Evil.Example. ")).isEqualTo(DOMAIN);
        assertThat(ModService.normaliseDomain(null)).isEmpty();
        assertThat(ModService.normaliseDomain("sub.evil.example")).isNotEqualTo(DOMAIN);
    }
}
