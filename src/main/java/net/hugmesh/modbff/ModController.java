package net.hugmesh.modbff;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import net.hugmesh.modbff.audit.ModAction;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.audit.ModActionType;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.federation.FederationApiClient;
import net.hugmesh.modbff.federation.SubmitModerationRequest;
import net.hugmesh.modbff.security.Roles;
import net.hugmesh.modbff.service.ModService;
import net.hugmesh.modbff.web.BanRequest;
import net.hugmesh.modbff.web.BlockRequest;
import net.hugmesh.modbff.web.DomainLockRequest;
import net.hugmesh.modbff.web.OwncastModRequest;
import net.hugmesh.modbff.web.RecommendRequest;

import java.util.Map;

/**
 * Moderator endpoints (reactive). Gating is DEFENCE IN DEPTH: the be-gateway denies
 * {@code /bff/mod/**} to non-MOD/ADMIN via the Postgres route-access rules, the
 * resource-server filter chain re-applies {@code hasAnyRole('MOD','ADMIN')} on the
 * path, AND {@code @PreAuthorize("hasAnyRole('MOD','ADMIN')")} re-checks at each
 * method.
 *
 * <p><b>Step-up MFA on the SENSITIVE write-effects.</b> The five platform-wide /
 * user-visible effects — {@code POST /block}, {@code POST|DELETE /ban} and
 * {@code POST|DELETE /domain-lock/{role}/{user}} — carry an EXTRA conjunct,
 * {@code @modStepUpGate.satisfied(authentication)}, on top of the role check: with
 * {@code app.mfa.enforce-sensitive-writes} armed, the caller must also carry the
 * {@code MFA_SATISFIED} marker or the call is 403 BEFORE {@link ModService} runs (so
 * no external effect and no audit row). The flag ships DARK, so by default the gate is
 * inert and these endpoints behave exactly as before — see
 * {@link net.hugmesh.modbff.security.ModStepUpGate} for the two-flag contract. The
 * remaining endpoints (reads, the moderation-queue write, the owncast stream actions)
 * keep the plain role gate.
 *
 * <p>The MOD surface is deliberately NARROW — no infra/server-admin endpoints:
 * <ul>
 *   <li><b>Moderation triage</b> — list/get the federation moderation queue
 *       (reactive WebClient to federation-api) and RECOMMEND a new request.</li>
 *   <li><b>Refer-to-admin</b> — escalate a user-removal / instance-block
 *       recommendation UP to an admin (federation-api {@code /moderation/{id}/refer}).
 *       A MOD NEVER removes a user directly; the refer is the only path.</li>
 *   <li><b>Server-wide block</b> — wire the external Matrix(tuwunel)/Mastodon(akkoma)
 *       admin clients to block a user/instance server-wide. The external call is
 *       STUBBED (homeserver admin shapes unconfirmed — see README) but the action
 *       is ALWAYS recorded in the local {@code mod_action} audit table.</li>
 *   <li><b>Federation modules</b> — deliver the MOD-accessible federation manifest
 *       (the role analog of admin-bff delivering admin modules).</li>
 *   <li><b>Audit</b> — read the local mod-action audit trail.</li>
 * </ul>
 */
@Tag(name = "Moderator", description = "MOD/ADMIN-gated moderation triage, refer-to-admin escalation, "
        + "server-wide Matrix/Mastodon block (audited), and federation module delivery.")
@RestController
@RequestMapping("/bff/mod")
@Validated
public class ModController {

    private static final Logger log = LoggerFactory.getLogger(ModController.class);

    private final FederationApiClient federation;
    private final MastodonAdminClient mastodon;
    private final ModActionRepository audit;
    private final ModService mod;

    public ModController(FederationApiClient federation,
                         MastodonAdminClient mastodon, ModActionRepository audit, ModService mod) {
        this.federation = federation;
        this.mastodon = mastodon;
        this.audit = audit;
        this.mod = mod;
    }

    // ── Moderation triage (federation-api queue) ───────────────────────
    @Operation(operationId = "listModeration",
            summary = "List the federation moderation queue (optionally by status).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Moderation queue returned"),
            @ApiResponse(responseCode = "400", description = "Invalid status parameter", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_MOD or ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasAnyRole('MOD','ADMIN')")
    @GetMapping("/moderation")
    public Mono<Map<String, Object>> listModeration(
            @RequestParam(required = false)
            @Size(max = 32, message = "status is too long")
            @Pattern(regexp = "[a-z-]*", message = "status has invalid characters")
            String status) {
        return federation.listModeration(status).collectList()
                .map(requests -> Map.of("requests", requests));
    }

    /**
     * Receive a user→mod recommendation and record it into the federation queue
     * (the user→mod→admin chain's middle step: a mod recommends). federation-api
     * derives the requester from the forwarded JWT.
     */
    @Operation(operationId = "recommendModeration",
            summary = "Record a moderation recommendation into the federation queue (mod recommends).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Recommendation submitted and audited"),
            @ApiResponse(responseCode = "400", description = "Validation failed — missing/invalid field", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_MOD or ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasAnyRole('MOD','ADMIN')")
    @PostMapping("/moderation")
    public Mono<ResponseEntity<Map<String, Object>>> recommend(@Valid @RequestBody RecommendRequest b,
                                                               Authentication auth) {
        String reason = str(b.reason());
        // Stamp the row with the caller's VALIDATED issuer-derived domain (mirrors
        // ModService.domain(auth)) so the brand's domain-scoped /audit read can see it —
        // the previous 6-arg record(...) hard-stamped 'default', hiding a branded mod's
        // rows from that brand's admin.
        String domain = ModService.domain(auth);
        return federation.submitModeration(new SubmitModerationRequest(b.kind(), b.target(), reason))
                .flatMap(submitted -> audit.record(actor(auth), ModActionType.FEDERATION_RECOMMEND,
                                "federation", b.target(), reason, "ok", domain)
                        .thenReturn(ResponseEntity.ok(Map.of("request", submitted))));
    }

    /**
     * Refer / escalate a moderation request UP to an admin. This is the ONLY mod
     * path for a user-removal / instance-block recommendation — a MOD never removes
     * directly. Also writes a local audit row.
     */
    @Operation(operationId = "referModeration",
            summary = "Refer a moderation request up to an admin (mod escalates — no direct removal).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Escalation submitted and audited"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_MOD or ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "404", description = "Moderation request not found", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasAnyRole('MOD','ADMIN')")
    @PostMapping("/moderation/{id}/refer")
    public Mono<Map<String, Object>> refer(@PathVariable long id, Authentication auth) {
        // 7-arg record with the caller's validated domain (see recommend) so a branded
        // mod's refer row is readable under that brand's scoped /audit read.
        String domain = ModService.domain(auth);
        return federation.referModeration(id)
                .flatMap(referred -> audit.record(actor(auth), ModActionType.FEDERATION_REFER,
                                "federation", "moderation-request:" + id, null, "ok", domain)
                        .thenReturn(Map.<String, Object>of("request", referred)));
    }

    // ── Server-wide block (external homeserver admin + local audit) ────
    /**
     * Block a user or instance server-wide on Matrix(tuwunel) or Mastodon(akkoma).
     * The external admin HTTP call is STUBBED (homeserver admin shapes unconfirmed),
     * but the action is ALWAYS recorded in {@code mod_action} with the external
     * outcome ({@code stubbed} / {@code ok} / {@code degraded:...}).
     *
     * <p>Body: {@code {platform: matrix|mastodon, scope: user|instance, target, reason?}}.
     */
    @Operation(operationId = "blockServerWide",
            summary = "Block a user/instance server-wide on Matrix/Mastodon (external STUBBED → 202 pending, locally audited).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Block applied on the homeserver (real OK)"),
            @ApiResponse(responseCode = "202", description = "Pending-reconcile — homeserver call STUBBED/degraded; action audited"),
            @ApiResponse(responseCode = "400", description = "Validation failed — invalid platform/scope/target", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_MOD or ROLE_ADMIN, step-up MFA is required but not satisfied, or target is privileged / cross-tenant", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasAnyRole('MOD','ADMIN') and @modStepUpGate.satisfied(authentication)")
    @PostMapping("/block")
    public Mono<ResponseEntity<Map<String, Object>>> block(@Valid @RequestBody BlockRequest b,
                                                           Authentication auth) {
        // Routed through ModService.block(...), which runs the SAME below-them /
        // cross-tenant guards as ban/lift/domain-lock — guardNotSelf → guardSameTenant →
        // guardNotPrivileged — and the platform-role assertion, ALL BEFORE any external
        // homeserver call or audit row. (The previous inline path SKIPPED those guards,
        // so a brand-X MOD could block a brand-Y / privileged target.) The service also
        // stamps the audit row with the caller's issuer-derived domain.
        return mod.block(b.platformLower(), b.scopeLower(), str(b.target()), str(b.reason()), auth)
                .map(result -> {
                    // OUTCOME CONTRACT: a STUBBED / degraded / breaker-open external block
                    // did NOT land the homeserver effect, so NEVER return 200 "blocked" —
                    // return 202 pending-reconcile. Only a real OK is a 200.
                    Map<String, Object> out = result.body();
                    return result.outcome().isOk()
                            ? ResponseEntity.ok(out)
                            : ResponseEntity.status(HttpStatus.ACCEPTED).body(out);
                });
    }

    // ── Access-role ban / lift (write the access_suspension desired-state) ──
    /**
     * Ban a user from a platform-access role. Writes the {@code access_suspension}
     * desired-state in admin-bff (the single-writer reconcile loop applies the Casdoor +
     * homeserver effect) and records a DEDUPED local {@code mod_action} row, then returns
     * {@code 202 {state:'pending-reconcile'}} — NEVER a synchronous 200 "banned", because
     * the effect is asynchronous. Guards (defence in depth, re-checked in {@link ModService}):
     * a MOD may not ban themselves, nor a {@code ROLE_ADMIN}/{@code ROLE_MOD} target (403).
     *
     * <p>Body: {@code {platform: matrix|mastodon|profile, target, ttlSeconds?, reason?, idempotencyKey?}}.
     */
    @Operation(operationId = "banUser",
            summary = "Ban a user from a platform-access role (writes desired-state → 202 pending-reconcile).")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Pending-reconcile — desired-state written; reconcile loop applies the effect"),
            @ApiResponse(responseCode = "400", description = "Validation failed — missing/invalid field", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Step-up MFA not satisfied, self-ban, privileged target, or cross-tenant attempt denied", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasAnyRole('MOD','ADMIN') and @modStepUpGate.satisfied(authentication)")
    @PostMapping("/ban")
    public Mono<ResponseEntity<Map<String, Object>>> ban(@Valid @RequestBody BanRequest b, Authentication auth) {
        return mod.ban(b.platformLower(), str(b.target()), b.ttlSeconds(), str(b.reason()),
                        b.idempotencyKey(), b.notifyChannels(), b.emailOnly(), auth)
                .map(result -> ResponseEntity.status(HttpStatus.ACCEPTED).body(result.body()));
    }

    /**
     * Lift a previously written ban (clear the {@code access_suspension} desired-state +
     * record an {@code access.restore} row). Same {@code 202 pending-reconcile} contract.
     * Body identical to {@code POST /bff/mod/ban} ({@code ttlSeconds}/{@code reason} ignored).
     */
    @Operation(operationId = "liftBan",
            summary = "Lift a platform-access ban (clears desired-state → 202 pending-reconcile).")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Pending-reconcile — desired-state cleared; reconcile loop lifts the effect"),
            @ApiResponse(responseCode = "400", description = "Validation failed — missing/invalid field", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Step-up MFA not satisfied, self-lift, or cross-tenant attempt denied", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasAnyRole('MOD','ADMIN') and @modStepUpGate.satisfied(authentication)")
    @DeleteMapping("/ban")
    public Mono<ResponseEntity<Map<String, Object>>> lift(@Valid @RequestBody BanRequest b, Authentication auth) {
        return mod.lift(b.platformLower(), str(b.target()), b.idempotencyKey(), auth)
                .map(result -> ResponseEntity.status(HttpStatus.ACCEPTED).body(result.body()));
    }

    // ── Domain-lock / unlock (write domain_lock desired-state; ADD-semantics) ──
    /**
     * Domain-lock a user — force their traffic LOCAL-ONLY / no-federation. This is an
     * ADDITIVE marker ({@code role} ∈ {@code ROLE_MATRIX_DOMAINLOCKED} |
     * {@code ROLE_MASTODON_DOMAINLOCKED}); the user KEEPS their
     * {@code ROLE_MATRIX}/{@code ROLE_MASTODON} access (the gateway routes are
     * UNTOUCHED). Writes the {@code domain_lock} desired-state in admin-bff's SEPARATE
     * table (NOT {@code access_suspension} — different ADD-vs-REMOVE semantics) via the
     * {@link net.hugmesh.modbff.admin.AdminDomainLockClient}; the single-writer
     * reconcile loop applies the marker + the homeserver/egress force-local enforcement.
     * Returns {@code 202 {state:'pending-reconcile'}} — NEVER a synchronous 200, because
     * the effect is asynchronous. Records a DEDUPED local {@code mod_action} row.
     *
     * <p>Below-them guard (defence in depth, re-checked in {@link ModService}): a MOD may
     * NOT domain-lock themselves, nor a {@code ROLE_ADMIN}/{@code ROLE_MOD} target (403).
     *
     * <p>Optional body: {@code {reason?, idempotencyKey?}}.
     */
    @Operation(operationId = "domainLockUser",
            summary = "Domain-lock a user (force local-only; writes desired-state → 202 pending-reconcile).")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Pending-reconcile — domain-lock desired-state written"),
            @ApiResponse(responseCode = "400", description = "Invalid role path variable", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Step-up MFA not satisfied, self-lock, privileged target, or cross-tenant attempt denied", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasAnyRole('MOD','ADMIN') and @modStepUpGate.satisfied(authentication)")
    @PostMapping({"/domain-lock/{role}/{user}", "/domain-lock/{role}/{user}/"})
    public Mono<ResponseEntity<Map<String, Object>>> domainLock(
            @PathVariable
            @Pattern(regexp = "ROLE_MATRIX_DOMAINLOCKED|ROLE_MASTODON_DOMAINLOCKED",
                    message = "role must be ROLE_MATRIX_DOMAINLOCKED or ROLE_MASTODON_DOMAINLOCKED")
            String role,
            @PathVariable @Size(max = 400, message = "user is too long") String user,
            @Valid @RequestBody(required = false) DomainLockRequest body,
            Authentication auth) {
        DomainLockRequest b = body == null ? DomainLockRequest.empty() : body;
        return mod.domainLock(role, str(user), str(b.reason()), b.idempotencyKey(), auth)
                .map(result -> ResponseEntity.status(HttpStatus.ACCEPTED).body(result.body()));
    }

    /**
     * Domain-UNLOCK a user — clear the {@code domain_lock} desired-state + record a
     * {@code domain.unlock} audit row. The reconcile loop drops the
     * {@code ROLE_*_DOMAINLOCKED} marker + stops gating on the next tick (past local-only
     * posts correctly stay local). Same below-them guard + {@code 202 pending-reconcile}
     * contract as the lock. Optional body identical (reason ignored on unlock).
     */
    @Operation(operationId = "domainUnlockUser",
            summary = "Domain-unlock a user (clears desired-state → 202 pending-reconcile).")
    @ApiResponses({
            @ApiResponse(responseCode = "202", description = "Pending-reconcile — domain-lock desired-state cleared"),
            @ApiResponse(responseCode = "400", description = "Invalid role path variable", content = @Content),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Step-up MFA not satisfied, self-unlock, or cross-tenant attempt denied", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasAnyRole('MOD','ADMIN') and @modStepUpGate.satisfied(authentication)")
    @DeleteMapping({"/domain-lock/{role}/{user}", "/domain-lock/{role}/{user}/"})
    public Mono<ResponseEntity<Map<String, Object>>> domainUnlock(
            @PathVariable
            @Pattern(regexp = "ROLE_MATRIX_DOMAINLOCKED|ROLE_MASTODON_DOMAINLOCKED",
                    message = "role must be ROLE_MATRIX_DOMAINLOCKED or ROLE_MASTODON_DOMAINLOCKED")
            String role,
            @PathVariable @Size(max = 400, message = "user is too long") String user,
            @Valid @RequestBody(required = false) DomainLockRequest body,
            Authentication auth) {
        DomainLockRequest b = body == null ? DomainLockRequest.empty() : body;
        return mod.domainUnlock(role, str(user), b.idempotencyKey(), auth)
                .map(result -> ResponseEntity.status(HttpStatus.ACCEPTED).body(result.body()));
    }

    // ── OWNCAST live-stream moderation (owncast-bff effector + ledger row) ──
    /**
     * HIDE a target owner's owncast stream — force {@code visibility=internal} in the
     * moderator's brand via owncast-bff's {@code /bff/owncast/mod} surface (which
     * re-derives the moderator identity + brand from the FORWARDED bearer and journals
     * locally), then record an {@code owncast.hide} row in the central {@code mod_action}
     * ledger. The owncast effect is SYNCHRONOUS: an {@code ok} outcome returns
     * {@code 200 {state:'applied'}}; a degraded owncast-bff returns
     * {@code 202 {state:'not-applied'}} (there is NO reconcile loop on this surface —
     * the body says so honestly). A target with no stream in the brand is a real 404.
     * Guards (re-checked in {@link ModService}): self / cross-tenant / privileged
     * target → 403 BEFORE any effect.
     *
     * <p>Optional body: {@code {reason?}}.
     */
    @Operation(operationId = "owncastHideStream",
            summary = "Hide a target owner's owncast stream (synchronous effector call → 200 applied "
                    + "or 202 not-applied; recorded in the central mod ledger).")
    @PreAuthorize("hasAnyRole('MOD','ADMIN')")
    @PostMapping("/owncast/streams/{ownerSubject}/hide")
    public Mono<ResponseEntity<Map<String, Object>>> owncastHide(
            @PathVariable @Size(max = 400, message = "ownerSubject is too long") String ownerSubject,
            @Valid @RequestBody(required = false) OwncastModRequest body,
            Authentication auth) {
        return mod.owncastHide(str(ownerSubject), reasonOf(body), auth).map(ModController::owncastResponse);
    }

    /**
     * KILL a target owner's stream — owncast-bff writes an active
     * {@code owncast_grant(banned)} (its ban&gt;grant guard then denies the owner's
     * public broadcast) AND hides the stream; an {@code owncast.kill} ledger row is
     * recorded here. Same synchronous outcome contract + guards as the hide.
     */
    @Operation(operationId = "owncastKillStream",
            summary = "Kill a target owner's stream (owncast ban + hide → 200 applied or 202 "
                    + "not-applied; recorded in the central mod ledger).")
    @PreAuthorize("hasAnyRole('MOD','ADMIN')")
    @PostMapping("/owncast/streams/{ownerSubject}/kill")
    public Mono<ResponseEntity<Map<String, Object>>> owncastKill(
            @PathVariable @Size(max = 400, message = "ownerSubject is too long") String ownerSubject,
            @Valid @RequestBody(required = false) OwncastModRequest body,
            Authentication auth) {
        return mod.owncastKill(str(ownerSubject), reasonOf(body), auth).map(ModController::owncastResponse);
    }

    /**
     * RESTORE a killed owner — owncast-bff CASes the active broadcast ban
     * active→revoked (audit-preserving; no auto-republish — the owner re-chooses
     * visibility); an {@code owncast.restore} ledger row is recorded here. REMEDIAL:
     * only the cross-tenant guard applies (mirrors ban-vs-lift).
     */
    @Operation(operationId = "owncastRestoreStream",
            summary = "Restore a killed owncast owner (lift the broadcast ban → 200 applied or 202 "
                    + "not-applied; recorded in the central mod ledger).")
    @PreAuthorize("hasAnyRole('MOD','ADMIN')")
    @PostMapping("/owncast/streams/{ownerSubject}/restore")
    public Mono<ResponseEntity<Map<String, Object>>> owncastRestore(
            @PathVariable @Size(max = 400, message = "ownerSubject is too long") String ownerSubject,
            @Valid @RequestBody(required = false) OwncastModRequest body,
            Authentication auth) {
        return mod.owncastRestore(str(ownerSubject), reasonOf(body), auth).map(ModController::owncastResponse);
    }

    /** OUTCOME CONTRACT: only a real synchronous OK is a 200 applied; a degraded
     *  effector call is 202 not-applied (the honest envelope carries the reason). */
    private static ResponseEntity<Map<String, Object>> owncastResponse(ModService.OwncastModResult result) {
        return result.outcome().isOk()
                ? ResponseEntity.ok(result.body())
                : ResponseEntity.status(HttpStatus.ACCEPTED).body(result.body());
    }

    private static String reasonOf(OwncastModRequest body) {
        return body == null ? null : str(body.reason());
    }

    // ── Federation modules (MOD-accessible manifest) ───────────────────
    @Operation(operationId = "listModules",
            summary = "Deliver the MOD-accessible federation modules manifest.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Federation modules manifest returned"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_MOD or ROLE_ADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasAnyRole('MOD','ADMIN')")
    @GetMapping("/modules")
    public Mono<Map<String, Object>> modules() {
        return federation.manifest().map(manifest -> Map.of("manifest", manifest));
    }

    // ── System-finding queue (automated edge-AI moderation findings) ───
    /**
     * List the SYSTEM-FINDING queue — automated edge-AI avatar/image moderation findings
     * a moderator triages (the companion AUTOMATED queue to the HUMAN moderation queue
     * above; filed by user-bff's pre-publish avatar vision check → federation-api). Proxies
     * federation-api {@code GET /api/federation/findings}, which DOMAIN-SCOPES the result
     * from the forwarded JWT issuer — a per-brand mod sees ONLY their own brand's findings;
     * a SUPERADMIN (reaching this gate via the role hierarchy) spans all brands. Optional
     * {@code ?status=held|dismissed|actioned} (omit = the full queue).
     */
    @Operation(operationId = "listFindings",
            summary = "List the automated edge-AI system-finding queue (optionally by status).")
    @PreAuthorize("hasAnyRole('MOD','ADMIN')")
    @GetMapping("/findings")
    public Mono<Map<String, Object>> listFindings(
            @RequestParam(required = false)
            @Pattern(regexp = "held|dismissed|actioned",
                    message = "status must be held | dismissed | actioned")
            String status) {
        return federation.listFindings(status).collectList()
                .map(findings -> Map.of("findings", findings));
    }

    /**
     * Resolve a held system finding: {@code actioned=true} marks it ACTIONED (the mod took
     * action), {@code false} DISMISSES it (the mod cleared it). Proxies federation-api
     * {@code POST /api/federation/findings/{id}/resolve} (which records the reviewer from
     * the forwarded JWT subject and 404s a cross-domain id — the cross-tenant boundary is
     * enforced server-side), then writes a DOMAIN-STAMPED local {@code mod_action} audit
     * row (mirrors recommend/refer) so the resolve is first-class in this brand's
     * moderation trail.
     */
    @Operation(operationId = "resolveFinding",
            summary = "Resolve a held system finding (?actioned=true actions it, false dismisses it).")
    @PreAuthorize("hasAnyRole('MOD','ADMIN')")
    @PostMapping("/findings/{id}/resolve")
    public Mono<Map<String, Object>> resolveFinding(@PathVariable long id,
                                                    @RequestParam boolean actioned,
                                                    Authentication auth) {
        // Stamp the audit row with the caller's VALIDATED issuer-derived domain (mirrors
        // recommend/refer) so the brand's domain-scoped /audit read can see the row.
        String domain = ModService.domain(auth);
        String disposition = actioned ? "actioned" : "dismissed";
        return federation.resolveFinding(id, actioned)
                .flatMap(resolved -> audit.record(actor(auth), ModActionType.FEDERATION_FINDING_RESOLVE,
                                "federation", "system-finding:" + id, disposition, "ok", domain)
                        .thenReturn(Map.<String, Object>of("finding", resolved)));
    }

    // ── Local mod-action audit trail (DOMAIN-SCOPED) ───────────────────
    /**
     * Read the local moderator-action audit trail. DOMAIN-SCOPED: a per-domain
     * MOD/ADMIN sees ONLY their OWN brand's rows — the domain is read off the VALIDATED
     * {@code DOMAIN_<x>} authority (issuer-derived, not a user claim) and used as a
     * WHERE predicate, so a brand-X moderator can never read brand-Y's audit rows. A
     * {@code SUPERADMIN} (the cross-domain infra control plane) reads UNSCOPED across
     * every brand. {@code mine=true} additionally narrows to the caller's own actor.
     *
     * <p>Fail-closed: a principal with an ambiguous DOMAIN_ authority set (zero or
     * &gt;1 — the injection signature) resolves to a {@code null} domain via
     * {@link Roles#domainOf(Authentication)}, and the scoped repository query returns an
     * EMPTY result rather than leaking another brand's rows.
     *
     * <p>BOUNDED (unbounded-table DoS hardening): the read returns at most the NEWEST
     * {@code limit} rows ({@code ORDER BY ts DESC LIMIT}), defaulting to
     * {@link ModActionRepository#DEFAULT_AUDIT_LIMIT} and HARD-CAPPED at
     * {@link ModActionRepository#MAX_AUDIT_LIMIT}. A caller-supplied {@code ?limit=} is
     * clamped server-side here (and clamped AGAIN in the facade as defense-in-depth), so
     * no caller can stream the whole {@code mod_action} table into memory. The clamp
     * applies UNIFORMLY to every variant (superadmin/per-domain, all/mine).
     */
    @Operation(operationId = "listAuditTrail",
            summary = "Read the local moderator-action audit trail (domain-scoped; newest-first, capped; optionally just mine).")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Audit trail returned (domain-scoped; SUPERADMIN sees all brands; empty on ambiguous DOMAIN_ authority set)"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_MOD, ROLE_ADMIN, or ROLE_SUPERADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @PreAuthorize("hasAnyRole('MOD','ADMIN','SUPERADMIN')")
    @GetMapping("/audit")
    public Mono<Map<String, Object>> auditTrail(@RequestParam(required = false, defaultValue = "false") boolean mine,
                                                @RequestParam(required = false) Integer limit,
                                                Authentication auth) {
        boolean superadmin = Roles.isSuperadmin(auth);
        String actor = actor(auth);
        String domain = Roles.domainOf(auth);
        // Clamp the caller-influenced page size to [1, MAX] server-side; a missing/blank
        // limit falls back to the default. The facade clamps again (defense-in-depth).
        int capped = ModActionRepository.clampLimit(limit == null ? ModActionRepository.DEFAULT_AUDIT_LIMIT : limit);
        Flux<ModAction> rows = superadmin
                // SUPERADMIN: cross-domain, no DOMAIN predicate (sees every brand).
                ? (mine ? audit.listByActor(actor, capped) : audit.list(capped))
                // Per-domain MOD/ADMIN: scoped to their own DOMAIN_<x> (deny cross-domain).
                : mine ? audit.listByActorForDomain(actor, domain, capped)
                        : audit.listForDomain(domain, capped);
        return rows.collectList().map(actions -> Map.<String, Object>of("actions", actions));
    }

    // ── Helpers ────────────────────────────────────────────────────────
    /** The acting moderator's identity for audit attribution (JWT subject/name). */
    private static String actor(Authentication auth) {
        return auth == null ? "mod" : auth.getName();
    }

    /** Null-or-blank-safe String coercion (a blank/empty value collapses to null). */
    private static String str(Object o) {
        if (o == null) return null;
        String s = o.toString().trim();
        return s.isEmpty() ? null : s;
    }
}
