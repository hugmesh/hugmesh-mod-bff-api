package systems.hugmesh.modbff.federation;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

/**
 * TEST/SEED-ONLY finding-fixture endpoint — {@code POST /bff/mod/findings/test-seed}.
 * Exists SOLELY so an e2e test, already authenticated as a real MOD/ADMIN persona, can
 * get a REAL {@code held} {@code system_findings} row created WITHOUT depending on the
 * platform's non-deterministic edge-AI avatar-vision pre-publish check (the only
 * production filer) — the sole other production writer,
 * {@code POST /api/federation/findings} on federation-api, is authenticated-self-only
 * and is not proxied to the browser by the gateway, so no e2e layer can otherwise reach
 * it deterministically (see {@code findings-panel.feature} / {@code findings-triage
 * .feature} in hugmesh-mod-ui for the reachability analysis this closes).
 *
 * <p><b>Not a parallel write path.</b> This controller does NOT talk to a repository or
 * hand-write a row: it calls {@link FederationApiClient#fileFinding}, which POSTs the
 * EXACT SAME {@code /api/federation/findings} federation-api endpoint the real pre-publish
 * check drives, so the {@code SystemFindingService} write, its {@code held} status, and
 * its domain-stamping all behave identically to production. The only thing this
 * controller adds is a browser-reachable, deterministic ENTRY POINT to that endpoint.
 *
 * <p><b>No new IDOR.</b> federation-api's {@code file()} is self-only: the finding's
 * {@code subject} is ALWAYS the forwarded JWT's own subject, never a request field
 * (enforced upstream, unchanged by this controller). Because {@link BearerForwardingFilter}
 * forwards the CALLING mod's own bearer, the seeded finding's content-owner is the
 * calling mod/admin themselves — nobody else. Sits under the ordinary
 * {@code /bff/mod/**} MOD/ADMIN floor (no new route class, no widened role gate).
 *
 * <p><b>SHIPS DARK by default</b> — gated by {@code app.test-seed.enabled} (default
 * {@code false}), the same idiom hugmesh-user-bff-api uses for its notification
 * test-seed route. When the flag is off the route still exists (a misconfigured e2e run
 * gets a loud, honest 503 rather than a 404 that could be mistaken for "wrong path"), but
 * it performs NO write and reaches {@link FederationApiClient} ZERO times — never a
 * silent no-op 200. Set {@code APP_TEST_SEED_ENABLED=true} ONLY in the e2e/dev
 * compose+cluster profile; it MUST stay off in production.
 *
 * <p><b>KNOWN GAP, disclosed (not yet closed):</b> {@code hugmesh-generator}'s
 * {@code tests/stack/compose.local.yaml} does not yet set {@code APP_TEST_SEED_ENABLED}
 * for this service — that repo is out of scope for the stream that added this route.
 * Until that one-line compose change lands, this route stays a real 503 on the local
 * e2e stack (see this repo's README "Honest deferrals" section for the exact fix
 * needed). {@code mod-ui}'s {@code findings-triage.feature} round-trip scenarios are
 * validated OFFLINE ONLY against this PR (compile/discovery, not a live run).
 */
@Tag(name = "System Findings (TEST-SEED)", description = "TEST/SEED-ONLY. Ships dark behind "
        + "app.test-seed.enabled (default false). Files a real HELD system finding, owned by the "
        + "calling MOD/ADMIN, through the SAME federation-api production write path the pre-publish "
        + "edge-AI vision check uses — never a parallel write.")
@RestController
@RequestMapping("/bff/mod/findings/test-seed")
@PreAuthorize("hasAnyRole('MOD','ADMIN')")
@Validated
public class TestSeedFindingController {

    /** Default {@code surface} when the caller supplies none — lets a human glance at
     *  a finding and know it was test-seeded rather than filed by the real pre-publish
     *  check (which always stamps a real surface like {@code profile-avatar}). */
    static final String DEFAULT_SURFACE = "test-seed";
    /** Default {@code disposition}. Either {@code flagged}/{@code rejected} value is
     *  valid — the row lands {@code held} either way (federation-api's
     *  {@code SystemFindingService.file()} always sets {@code status=held} on file,
     *  independent of {@code disposition}). */
    static final String DEFAULT_DISPOSITION = "flagged";

    private final FederationApiClient federation;
    private final boolean enabled;

    public TestSeedFindingController(FederationApiClient federation,
                                     @Value("${app.test-seed.enabled:false}") boolean enabled) {
        this.federation = federation;
        this.enabled = enabled;
    }

    /** The seed request. There is deliberately NO subject/target field — the finding's
     *  content-owner is always the caller's own JWT subject (federation-api enforces
     *  this; nothing here could override it even if it tried). */
    public record SeedRequest(
            @Size(max = 64, message = "surface must be at most 64 chars") String surface,
            @Pattern(regexp = "flagged|rejected", message = "disposition must be flagged | rejected")
            String disposition) {}

    @Operation(summary = "TEST/SEED-ONLY: file a real HELD system finding, owned by the "
            + "calling MOD/ADMIN, through the production federation-api write path. "
            + "503 when app.test-seed.enabled=false (ships dark).")
    @PostMapping
    public Mono<SystemFindingDto> seed(@RequestBody(required = false) @Valid SeedRequest req) {
        if (!enabled) {
            // Honest disclosure: no bean toggle, no swallowed write — a real 503 so a
            // misconfigured e2e run FAILS instead of silently seeding nothing.
            return Mono.error(new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                    "test-seed is not enabled (app.test-seed.enabled=false)"));
        }
        String surface = (req == null || req.surface() == null || req.surface().isBlank())
                ? DEFAULT_SURFACE : req.surface();
        String disposition = (req == null || req.disposition() == null || req.disposition().isBlank())
                ? DEFAULT_DISPOSITION : req.disposition();
        return federation.fileFinding(surface, disposition);
    }
}
