package net.hugmesh.modbff.federation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/**
 * Reactive WebClient client of hugmesh-federation-api — this BFF is a CLIENT of
 * federation-api, never the other way round. The base URL defaults to the
 * in-cluster DNS name {@code http://hugmesh-federation-api.hugmesh-backend
 * .svc.cluster.local:8080} (overridable via {@code federation-api.base-url}; never
 * hardcoded without a default). Every call carries the CALLER's Casdoor JWT via the
 * {@link BearerForwardingFilter} wired into the injected {@link WebClient}, so
 * federation-api's own {@code @PreAuthorize('hasAnyRole MOD,ADMIN')} +
 * manifest visibility-filter see the original moderator.
 *
 * <p>Endpoints used (matched field-for-field to federation-api controllers):
 * <ul>
 *   <li>{@code GET  /api/federation/moderation[?status=...]} — list the
 *       moderation queue (a mod triages).</li>
 *   <li>{@code POST /api/federation/moderation} — submit a recommendation
 *       (the user→mod→admin chain's middle step: a mod records a
 *       recommendation).</li>
 *   <li>{@code POST /api/federation/moderation/{id}/refer} — refer/escalate a
 *       request UP to an admin (a MOD never decides/removes directly).</li>
 *   <li>{@code GET  /api/federation/manifest} — the MOD-accessible federation
 *       modules (already role/visibility-filtered server-side).</li>
 *   <li>{@code GET  /api/federation/findings[?status=...]} — list the SYSTEM-FINDING
 *       queue (automated edge-AI avatar/image moderation findings a mod triages;
 *       federation-api scopes it to the caller's issuer-derived domain).</li>
 *   <li>{@code POST /api/federation/findings/{id}/resolve?actioned=...} — resolve a
 *       held finding ({@code actioned=true} marks it actioned, {@code false}
 *       dismisses it).</li>
 * </ul>
 */
public class FederationApiClient {

    private static final Logger log = LoggerFactory.getLogger(FederationApiClient.class);

    private final WebClient http;

    public FederationApiClient(final WebClient webClient) {
        this.http = webClient;
    }

    /** List the moderation queue, optionally filtered by status. */
    public Flux<ModerationRequestDto> listModeration(String status) {
        return http.get()
                .uri(uri -> {
                    uri.path("/api/federation/moderation");
                    if (status != null && !status.isBlank()) uri.queryParam("status", status);
                    return uri.build();
                })
                .retrieve()
                .bodyToFlux(ModerationRequestDto.class);
    }

    /**
     * Submit a moderation recommendation (mod recommends). federation-api derives
     * the requester from the forwarded JWT subject, so only {kind,target,reason}
     * are sent.
     */
    public Mono<ModerationRequestDto> submitModeration(SubmitModerationRequest body) {
        return http.post()
                .uri("/api/federation/moderation")
                .bodyValue(body)
                .retrieve()
                .bodyToMono(ModerationRequestDto.class)
                .doOnSuccess(r -> log.info("[federation] submitted moderation request kind={} target={}",
                        body.kind(), body.target()));
    }

    /**
     * Refer/escalate a moderation request up to an admin. This is how a MOD acts
     * on a user-removal / instance-block recommendation: ESCALATE, never remove
     * directly. {@code id} is the federation-api {@code moderation_requests} id.
     */
    public Mono<ModerationRequestDto> referModeration(long id) {
        return http.post()
                .uri("/api/federation/moderation/{id}/refer", id)
                .retrieve()
                .bodyToMono(ModerationRequestDto.class)
                .doOnSuccess(r -> log.info("[federation] referred moderation request {} to admin", id));
    }

    /** The MOD-accessible federation manifest (server-side role/visibility-filtered). */
    public Mono<FederationManifestDto> manifest() {
        return http.get()
                .uri("/api/federation/manifest")
                .retrieve()
                .bodyToMono(FederationManifestDto.class);
    }

    /**
     * List the SYSTEM-FINDING queue (automated edge-AI avatar/image moderation
     * findings), optionally filtered by {@code status} ({@code held|dismissed|actioned}).
     * federation-api scopes the result to the forwarded JWT's issuer-derived domain
     * (a per-brand mod sees ONLY their own brand's findings; SUPERADMIN spans all).
     */
    public Flux<SystemFindingDto> listFindings(String status) {
        return http.get()
                .uri(uri -> {
                    uri.path("/api/federation/findings");
                    if (status != null && !status.isBlank()) uri.queryParam("status", status);
                    return uri.build();
                })
                .retrieve()
                .bodyToFlux(SystemFindingDto.class);
    }

    /**
     * Resolve a held system finding: {@code actioned=true} marks it {@code actioned},
     * {@code false} dismisses it. federation-api records the reviewer from the
     * forwarded JWT subject and 404s a cross-domain id, so this BFF passes only
     * {id, actioned}.
     */
    public Mono<SystemFindingDto> resolveFinding(long id, boolean actioned) {
        return http.post()
                .uri(uri -> uri.path("/api/federation/findings/{id}/resolve")
                        .queryParam("actioned", actioned)
                        .build(id))
                .retrieve()
                .bodyToMono(SystemFindingDto.class)
                .doOnSuccess(f -> log.info("[federation] resolved system finding {} actioned={}", id, actioned));
    }

    /**
     * TEST/SEED-ONLY passthrough: file a NEW {@code held} system finding through
     * federation-api's PRODUCTION write path ({@code POST /api/federation/findings}) —
     * the EXACT SAME endpoint (and {@code SystemFindingService}) the upstream user-bff
     * pre-publish avatar-vision check drives, never a parallel hand-written insert.
     * federation-api's file() endpoint is {@code isAuthenticated()} + self-only (the
     * {@code subject} is always the forwarded JWT's own subject, never a request
     * field), so — because {@link BearerForwardingFilter} forwards the CALLING mod's
     * own bearer — the seeded finding's content-owner is the calling mod/admin
     * themselves. No cross-user write capability is introduced. Called ONLY from
     * {@code TestSeedFindingController}, which ships dark behind
     * {@code app.test-seed.enabled} (default false).
     */
    public Mono<SystemFindingDto> fileFinding(String surface, String disposition) {
        return http.post()
                .uri("/api/federation/findings")
                .bodyValue(new FileFindingRequest(surface, disposition))
                .retrieve()
                .bodyToMono(SystemFindingDto.class)
                .doOnSuccess(f -> log.info("[federation] test-seed filed finding surface={} disposition={}",
                        surface, disposition));
    }

    /**
     * Wire shape of federation-api's {@code SystemFindingController.FileRequest} —
     * ONLY the two fields the test-seed caller supplies; the remaining optional
     * edge-AI fields ({@code classification}, {@code confidence}, {@code policyHit},
     * {@code perceptualHash}, {@code subjectRef}) are omitted (null on the wire),
     * exactly as a real pre-publish check would when it has no verdict for them.
     */
    private record FileFindingRequest(String surface, String disposition) {}
}
