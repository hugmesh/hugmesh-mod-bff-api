package net.hugmesh.modbff.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import net.hugmesh.modbff.admin.AdminDomainLockClient;
import net.hugmesh.modbff.admin.AdminSuspensionClient;
import net.hugmesh.modbff.admin.CasdoorRoleClient;
import net.hugmesh.modbff.admin.SuspensionOutcome;
import net.hugmesh.modbff.audit.ModAction;
import net.hugmesh.modbff.audit.ModActionKey;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.audit.ModActionType;
import net.hugmesh.modbff.external.BlockOutcome;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.external.MatrixAdminClient;
import net.hugmesh.modbff.federation.FederationApiClient;
import net.hugmesh.modbff.federation.ModerationRequestDto;
import net.hugmesh.modbff.federation.SubmitModerationRequest;
import net.hugmesh.modbff.model.PlatformKind;
import net.hugmesh.modbff.model.ScopeKind;
import net.hugmesh.modbff.notify.NotifyDirective;
import net.hugmesh.modbff.owncast.OwncastModClient;
import net.hugmesh.modbff.tube.TubeModClient;
import net.hugmesh.commons.security.DomainRegistry;
import net.hugmesh.modbff.security.Roles;
import net.hugmesh.commons.web.ApiException;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Moderation service layer — DEFENCE IN DEPTH. The controller's method-level
 * {@code @PreAuthorize} (and the gateway route rules + the resource-server chain) are
 * the first legs; this service RE-CHECKS the same authorisation invariants so an
 * authenticated MOD principal that slipped past a higher leg still cannot:
 * <ul>
 *   <li>ban themselves (self-ban → 403);</li>
 *   <li>moderate a target OUTSIDE the caller's tenant — a brand-X MOD banning /
 *       domain-locking / lifting a brand-Y user (cross-domain BOLA/BFLA → 403). The
 *       target's brand is resolved AUTHORITATIVELY against the caller's per-domain
 *       Casdoor org ({@link CasdoorRoleClient#belongsToDomain}) and asserted with
 *       {@link Roles#domainApplies}, fail-closed BEFORE the write is assembled.
 *       SUPERADMIN bypasses (cross-domain infra control plane);</li>
 *   <li>ban a privileged user — a {@code ROLE_ADMIN} or {@code ROLE_MOD} (→ 403),
 *       resolved via {@link CasdoorRoleClient} (gated stub-seam, see that class);</li>
 *   <li>drive a homeserver block on a platform the principal lacks the platform role
 *       for ({@code matrix}→{@code ROLE_MATRIX}, {@code mastodon}→{@code ROLE_MASTODON})
 *       unless they are {@code ROLE_ADMIN}.</li>
 * </ul>
 *
 * <p>A BAN does NOT apply Casdoor/homeserver state here — it writes the
 * {@code access_suspension} DESIRED-STATE in admin-bff ({@link AdminSuspensionClient})
 * and persists a deduped local {@code mod_action} row. The outcome is ALWAYS
 * {@code pending-reconcile} (or a degraded variant on a breaker-open admin-bff) —
 * never a synchronous "blocked" — because the reconcile loop applies the effect.
 */
@Service
public class ModService {

    private static final Logger log = LoggerFactory.getLogger(ModService.class);

    private final AdminSuspensionClient suspensions;
    private final AdminDomainLockClient domainLocks;
    private final CasdoorRoleClient roles;
    private final ModActionRepository audit;
    private final MatrixAdminClient matrix;
    private final MastodonAdminClient mastodon;
    private final OwncastModClient owncast;
    /** tube moderation effector; {@code null} until an implementation is registered
     *  (tube-bff-api has no moderation endpoint yet), in which case {@code tubeHide}
     *  refuses to run. */
    private final TubeModClient tube;
    /** federation-api client for the Matrix instance-block approval trail (decisions
     *  84a-d); {@code null} only through the legacy 7-arg constructor. */
    private final FederationApiClient federation;

    /** federation-api {@code moderation_requests.kind} for a remote-instance block —
     *  the exact vocabulary federation-api's {@code ModerationService.isKind} accepts and
     *  that its {@code POST /recommend-instance-block} hardcodes for a user's own filing. */
    static final String INSTANCE_BLOCK_KIND = "instance-block";
    /** The two OPEN {@code moderation_requests} statuses (84a); {@code approved}/{@code denied} are closed. */
    static final String STATUS_RECOMMENDED = "recommended";
    static final String STATUS_REFERRED = "referred";
    /** Per-call ceiling on each federation-api round trip made from the block path, so a
     *  hung federation-api can never hang a Block click whose mod_action row is already
     *  written — the leg reports {@code error} instead. */
    static final Duration FEDERATION_CALL_TIMEOUT = Duration.ofSeconds(10);
    /** federation-api {@code SubmitRequest.reason} is {@code @Size(max = 1024)} while a
     *  block reason may be up to 2048 ({@code BlockRequest}); a longer reason is clipped
     *  on the federation leg ONLY (the mod_action row keeps the full text), so a valid
     *  block can never earn a 400 that files nothing. */
    static final int FEDERATION_REASON_MAX = 1024;

    @Autowired
    public ModService(AdminSuspensionClient suspensions, AdminDomainLockClient domainLocks,
                      CasdoorRoleClient roles, ModActionRepository audit,
                      MatrixAdminClient matrix, MastodonAdminClient mastodon,
                      OwncastModClient owncast, FederationApiClient federation,
                      ObjectProvider<TubeModClient> tube) {
        this(suspensions, domainLocks, roles, audit, matrix, mastodon, owncast, federation,
                tube.getIfAvailable());
    }

    public ModService(AdminSuspensionClient suspensions, AdminDomainLockClient domainLocks,
                      CasdoorRoleClient roles, ModActionRepository audit,
                      MatrixAdminClient matrix, MastodonAdminClient mastodon,
                      OwncastModClient owncast, FederationApiClient federation,
                      TubeModClient tube) {
        this.suspensions = suspensions;
        this.domainLocks = domainLocks;
        this.roles = roles;
        this.audit = audit;
        this.matrix = matrix;
        this.mastodon = mastodon;
        this.owncast = owncast;
        this.federation = federation;
        this.tube = tube;
    }

    /** The 8-arg form, kept so existing hand-wired tests compile unchanged: no tube client. */
    public ModService(AdminSuspensionClient suspensions, AdminDomainLockClient domainLocks,
                      CasdoorRoleClient roles, ModActionRepository audit,
                      MatrixAdminClient matrix, MastodonAdminClient mastodon,
                      OwncastModClient owncast, FederationApiClient federation) {
        this(suspensions, domainLocks, roles, audit, matrix, mastodon, owncast, federation,
                (TubeModClient) null);
    }

    /**
     * Legacy constructor (pre decision 84) kept so existing hand-wired tests compile
     * unchanged. Spring never uses it (the 8-arg constructor is {@code @Autowired}).
     * With no {@link FederationApiClient} the Matrix instance-block leg reports
     * {@code federation.status = not-configured} and files nothing.
     */
    public ModService(AdminSuspensionClient suspensions, AdminDomainLockClient domainLocks,
                      CasdoorRoleClient roles, ModActionRepository audit,
                      MatrixAdminClient matrix, MastodonAdminClient mastodon,
                      OwncastModClient owncast) {
        this(suspensions, domainLocks, roles, audit, matrix, mastodon, owncast, null,
                (TubeModClient) null);
    }

    // ── BAN (write access_suspension desired-state) ────────────────────
    /**
     * Ban {@code target} from {@code platform}'s access role. Runs the self-ban +
     * privileged-target guards (service-layer re-check), records a DEDUPED audit row
     * (idempotent on a retry), writes the desired-state in admin-bff, and returns a
     * pending-reconcile result. The local row is persisted EVEN IF admin-bff is
     * degraded, so the moderator's intent is always auditable.
     */
    public Mono<BanResult> ban(String platform, String target, Long ttlSeconds, String reason,
                               String idempotencyKey, Authentication auth) {
        return ban(platform, target, ttlSeconds, reason, idempotencyKey,
                List.of(), false, auth);
    }

    /**
     * Ban {@code target} from {@code platform}, ALSO carrying the service-scoped
     * {@code @system} notification directive (Notifications PR6): {@code notifyChannels}
     * (scoped to {@code platform} via {@link NotifyDirective#resolve}) + {@code emailOnly}.
     * The directive is recorded on the {@code mod_action} row and forwarded to admin-bff's
     * suspension write — but the forwarded request NEVER carries the moderator's identity
     * (the neutral {@code @system} sender must not expose who moderated). Same guards +
     * dedup + pending-reconcile contract as the no-directive overload.
     */
    public Mono<BanResult> ban(String platform, String target, Long ttlSeconds, String reason,
                               String idempotencyKey, List<String> notifyChannels,
                               boolean emailOnly, Authentication auth) {
        String actor = actor(auth);
        String domain = domain(auth);
        boolean superadmin = Roles.isSuperadmin(auth);
        String role = roleForPlatform(platform);
        // Resolve the directive against the action's platform (service-scoped); off-scope
        // channels are dropped here, BEFORE anything is persisted or forwarded.
        NotifyDirective notify = NotifyDirective.resolve(platform, notifyChannels, emailOnly);
        // Mono.defer on each downstream guard so the Casdoor round-trips only run AFTER
        // the (cheaper, always-on) self-ban guard passes — a self-ban short-circuits
        // before any Casdoor call. The SAME-TENANT guard runs first of the two Casdoor
        // legs: a target whose brand can't be proven equal to the caller's is denied
        // BEFORE the privileged-role read, the dedup row, and the suspend() write.
        return guardNotSelf(actor, target)
                .then(Mono.defer(() -> guardSameTenant(target, domain, superadmin)))
                .then(Mono.defer(() -> guardNotPrivileged(target, domain, superadmin)))
                // Record the deduped audit row and apply (or skip) the desired-state write.
                .then(Mono.defer(() -> recordAndApplyBan(
                        platform, role, target, ttlSeconds, reason, idempotencyKey, actor, domain, notify)));
    }

    private Mono<BanResult> applyOrDedup(ModActionRepository.RecordedBan recorded, String role, String target,
                                         Long ttlSeconds, String reason, NotifyDirective notify) {
        if (!recorded.fresh()) {
            // Deduped retry: the desired-state was already written on the first call;
            // do not re-trigger the effect. Report the persisted pending row.
            log.info("[ban] dedup hit — role={} target={} already recorded (id={})",
                    role, target, recorded.action().id());
            return Mono.just(BanResult.pending(recorded.action(), true));
        }
        // Forward the ttl/reason + the (service-scoped) notify directive to admin-bff.
        // NOTE: the actor is DELIBERATELY NOT forwarded — the neutral @system sender must
        // never learn (or surface) who moderated. When NO notification was requested we
        // use the legacy directive-less write so the wire body is byte-for-byte unchanged.
        Mono<SuspensionOutcome> write = (notify.any() || notify.emailOnly())
                ? suspensions.suspend(role, target, ttlSeconds, reason, notify.channels(), notify.emailOnly())
                : suspensions.suspend(role, target, ttlSeconds, reason);
        return write.map(outcome -> BanResult.of(recorded.action(), outcome, false));
    }

    /**
     * Build the dedup key, record the intent row, and then either skip (dedup hit) or
     * forward the desired-state write to admin-bff. Extracted from the ban() flatMap to
     * keep the reactive chain's lambda bodies within the 10-line Checkstyle limit.
     */
    private Mono<BanResult> recordAndApplyBan(String platform, String role, String target,
                                              Long ttlSeconds, String reason, String idempotencyKey,
                                              String actor, String domain, NotifyDirective notify) {
        // Thread the domain into the dedup key so two brands' Casdoor subjects never collide x-tenant.
        String dedupKey = ModActionKey.ban(ModActionType.ACCESS_SUSPEND, role, target, actor, domain, idempotencyKey);
        // Compute the optional TTL expiry timestamp before any async step.
        LocalDateTime expiresAt = ttlSeconds == null ? null : LocalDateTime.now().plusSeconds(ttlSeconds);
        // Persist the directive on the row only when a notification was requested; the
        // no-notify path uses the legacy 10-arg overload so the row is byte-for-byte unchanged.
        Mono<ModActionRepository.RecordedBan> record =
                (notify.any() || notify.emailOnly())
                        ? audit.recordBan(dedupKey, actor, ModActionType.ACCESS_SUSPEND, "access",
                                target, reason, banType(platform), expiresAt, "pending", domain,
                                notify.toCsv(), notify.emailOnly() ? Boolean.TRUE : null)
                        : audit.recordBan(dedupKey, actor, ModActionType.ACCESS_SUSPEND, "access",
                                target, reason, banType(platform), expiresAt, "pending", domain);
        // Delegate the fresh-vs-dedup decision and the actual desired-state write to applyOrDedup.
        return record.flatMap(recorded -> applyOrDedup(recorded, role, target, ttlSeconds, reason, notify));
    }

    /**
     * Build the dedup key, record the restore row, and then either skip (dedup hit) or
     * call clear() to forward the lift desired-state to admin-bff.
     */
    private Mono<BanResult> recordAndApplyLift(String role, String platform, String target,
                                               String actor, String domain, String idempotencyKey) {
        // Build a dedup key scoped to this actor, target, domain, and idempotency token.
        String dedupKey = ModActionKey.ban(ModActionType.ACCESS_RESTORE, role, target, actor, domain, idempotencyKey);
        // Record the restore intent (idempotent on dedup_key) before any desired-state write.
        return audit.recordBan(dedupKey, actor, ModActionType.ACCESS_RESTORE, "access",
                        target, null, banType(platform), null, "pending", domain)
                .flatMap(recorded -> {
                    // Dedup hit: the clear() was already issued; return the persisted pending row.
                    if (!recorded.fresh()) {
                        return Mono.just(BanResult.pending(recorded.action(), true));
                    }
                    // Fresh row: forward the clear desired-state to admin-bff and map the outcome.
                    return suspensions.clear(role, target)
                            .map(outcome -> BanResult.of(recorded.action(), outcome, false));
                });
    }

    /**
     * Build the dedup key, record the domain-lock row, and then either skip (dedup hit)
     * or call lock() to forward the desired-state to admin-bff.
     */
    private Mono<LockResult> recordAndApplyLock(String role, String target,
                                                String reason, String actor, String domain, String idempotencyKey) {
        // Build a dedup key scoped to this actor, target, domain, and idempotency token.
        String dedupKey = ModActionKey.ban(ModActionType.DOMAIN_LOCK, role, target, actor, domain, idempotencyKey);
        // Record the domain-lock intent (idempotent on dedup_key) before any desired-state write.
        return audit.recordBan(dedupKey, actor, ModActionType.DOMAIN_LOCK, "domain-lock",
                        target, reason, "user", null, "pending", domain)
                // Delegate the fresh-vs-dedup decision and the actual lock write to a named helper.
                .flatMap(recorded -> applyLockOrDedup(recorded, role, target, reason));
    }

    /**
     * Decide whether the domain-lock desired-state write should be issued (fresh row) or
     * skipped (dedup hit on an already-recorded intent row). Extracted to keep the
     * recordAndApplyLock flatMap body within the 10-line Checkstyle limit.
     */
    private Mono<LockResult> applyLockOrDedup(ModActionRepository.RecordedBan recorded,
                                              String role, String target, String reason) {
        // Dedup hit: the lock() was already issued; return the persisted pending row.
        if (!recorded.fresh()) {
            log.info("[domain-lock] dedup hit — role={} target={} already recorded (id={})",
                    role, target, recorded.action().id());
            return Mono.just(LockResult.pending(recorded.action(), true));
        }
        // Fresh row: forward the lock desired-state to admin-bff and map the outcome.
        return domainLocks.lock(role, target, reason)
                .map(outcome -> LockResult.of(recorded.action(), outcome, false));
    }

    /**
     * Build the dedup key, record the domain-unlock row, and then either skip (dedup hit)
     * or call unlock() to forward the desired-state to admin-bff.
     */
    private Mono<LockResult> recordAndApplyUnlock(String role, String target,
                                                  String actor, String domain, String idempotencyKey) {
        // Build a dedup key scoped to this actor, target, domain, and idempotency token.
        String dedupKey = ModActionKey.ban(ModActionType.DOMAIN_UNLOCK, role, target, actor, domain, idempotencyKey);
        // Record the unlock intent (idempotent on dedup_key) before any desired-state write.
        return audit.recordBan(dedupKey, actor, ModActionType.DOMAIN_UNLOCK, "domain-lock",
                        target, null, "user", null, "pending", domain)
                .flatMap(recorded -> {
                    // Dedup hit: the unlock() was already issued; return the persisted pending row.
                    if (!recorded.fresh()) {
                        return Mono.just(LockResult.pending(recorded.action(), true));
                    }
                    // Fresh row: forward the unlock desired-state to admin-bff and map the outcome.
                    return domainLocks.unlock(role, target)
                            .map(outcome -> LockResult.of(recorded.action(), outcome, false));
                });
    }

    /**
     * Assert the caller's platform role, dispatch the external homeserver block call,
     * then record the audit row. Extracted from the block() flatMap to keep lambda bodies
     * within the 10-line Checkstyle limit.
     */
    private Mono<BlockResult> assertAndApplyBlock(String platform, String target, String reason,
                                                  String actor, String domain, boolean user,
                                                  Authentication auth) {
        // Platform-role re-check (defence in depth): throws 403 before any homeserver/audit effect.
        assertPlatformRole(platform, auth);
        // Route matrix|mastodon to the appropriate homeserver client; profile/null stays STUBBED.
        // MATRIX + user is special-cased to matrixUserBlock (decision 51) instead of the
        // homeserver client directly — see that method's javadoc.
        Mono<BlockOutcome> external = switch (PlatformKind.fromWire(platform)) {
            case MATRIX   -> user ? matrixUserBlock(target, reason) : matrix.blockInstance(target);
            case MASTODON -> user ? mastodon.blockUser(target) : mastodon.blockInstance(target);
            case null, default -> Mono.just(BlockOutcome.STUBBED);
        };
        String action = blockActionFor(platform, user);
        boolean matrixInstance = !user && PlatformKind.MATRIX == PlatformKind.fromWire(platform);
        // Record the audit row after the external call resolves, then wrap into BlockResult.
        // The mod_action row is written FIRST, so a Matrix instance block's federation-api
        // leg (decisions 84a-d) can never cost the moderator their audited intent.
        return external.flatMap(outcome -> audit.record(actor, action, platform, target,
                        reason, outcome.result(), domain)
                .flatMap(recorded -> matrixInstance
                        ? fileInstanceBlockRequest(target, reason)
                                .map(filing -> new BlockResult(recorded, outcome, filing))
                        : Mono.just(new BlockResult(recorded, outcome))));
    }

    // ── Matrix instance block → federation-api approval trail (decisions 84a-d) ──
    /**
     * Route a Matrix INSTANCE block into federation-api's {@code moderation_requests}
     * submit → refer → decide trail (hugmesh-federation-api#7; the approved row is what
     * hugmesh-generator#564's apply job will read). Operator answers, 2026-09-23:
     * <ul>
     *   <li><b>84a = B</b> — look first: list the OPEN rows ({@code recommended} AND
     *       {@code referred}), keep those of kind {@code instance-block} whose target is
     *       this domain, and file only when none is open. A user's own
     *       {@code /recommend-instance-block} row counts as open and its id is reused.</li>
     *   <li><b>84c = A</b> — the Block click IS the moderator's escalation: a fresh
     *       filing is submit THEN refer (lands {@code referred}, moderator recorded as
     *       referrer); an open row still {@code recommended} is referred; an open row
     *       already {@code referred} is reused with no write.</li>
     *   <li><b>84b = A</b> — every call carries the moderator's OWN token
     *       ({@code BearerForwardingFilter}; no service identity). A 401 (a native-login
     *       moderator whose Casdoor swap failed, or {@code app.bff-exchange} off) does NOT
     *       fail the block: the mod_action row is already written and the result carries
     *       {@code federation.status = unauthorized}.</li>
     *   <li><b>84d = A</b> — the resulting {@code moderation_requests} id is surfaced as
     *       its own response field ({@link BlockResult#body()}).</li>
     * </ul>
     * Never errors: every failure collapses to a {@link FederationFiling} naming it.
     *
     * <p>Known limits, stated rather than hidden: the look-then-file pair is not atomic
     * (two moderators blocking the same domain in the same instant can each file — the
     * duplicate-proof option was 84a = C, not chosen); and a SUPERADMIN's list spans every
     * brand, so a superadmin block may reuse another brand's open row for the same domain.
     */
    private Mono<FederationFiling> fileInstanceBlockRequest(String target, String reason) {
        if (federation == null) {
            return Mono.just(FederationFiling.NOT_CONFIGURED);
        }
        return Mono.zip(openRows(STATUS_REFERRED, target), openRows(STATUS_RECOMMENDED, target))
                .flatMap(open -> open.getT1().stream().findFirst()
                        .map(referred -> Mono.just(FederationFiling.reused(referred)))
                        .orElseGet(() -> open.getT2().stream().findFirst()
                                .map(recommended -> referOpen(recommended.id(), FederationFiling.REFERRED_EXISTING))
                                .orElseGet(() -> submitAndRefer(target, reason))))
                // An empty completion anywhere on the leg (e.g. a 2xx submit with no body)
                // must still yield a result, or the block would answer a bodiless 200.
                .switchIfEmpty(Mono.fromSupplier(() -> FederationFiling.failed(
                        new IllegalStateException("federation-api returned no body"), null)))
                .onErrorResume(e -> Mono.just(FederationFiling.failed(e, null)));
    }

    /** The open rows of one status for this domain's instance block, newest first
     *  (federation-api orders by ts desc). */
    private Mono<List<ModerationRequestDto>> openRows(String status, String target) {
        String wanted = normaliseDomain(target);
        return federation.listModeration(status)
                .filter(r -> INSTANCE_BLOCK_KIND.equals(r.kind()) && status.equals(r.status())
                        && r.id() != null && wanted.equals(normaliseDomain(r.target())))
                .collectList()
                .timeout(FEDERATION_CALL_TIMEOUT);
    }

    /** No open row: submit (lands {@code recommended}) THEN refer the new id (84c). */
    private Mono<FederationFiling> submitAndRefer(String target, String reason) {
        return federation.submitModeration(new SubmitModerationRequest(INSTANCE_BLOCK_KIND, target,
                        clipReason(reason)))
                .timeout(FEDERATION_CALL_TIMEOUT)
                .flatMap(submitted -> submitted.id() == null
                        ? Mono.just(FederationFiling.failed(new IllegalStateException("submit returned no id"), null))
                        : referOpen(submitted.id(), FederationFiling.FILED));
    }

    /** Refer {@code id}; a refer failure keeps the id (the row exists, still {@code recommended}). */
    private Mono<FederationFiling> referOpen(long id, String status) {
        return federation.referModeration(id)
                .timeout(FEDERATION_CALL_TIMEOUT)
                .map(referred -> new FederationFiling(status, id, referred.status(), null))
                .switchIfEmpty(Mono.fromSupplier(() -> FederationFiling.failed(
                        new IllegalStateException("refer returned no body"), id)))
                .onErrorResume(e -> Mono.just(FederationFiling.failed(e, id)));
    }

    /** Fit a block reason into federation-api's {@code reason} limit: unchanged when it
     *  fits, else cut to {@link #FEDERATION_REASON_MAX} chars ending in an ellipsis, never
     *  splitting a surrogate pair. */
    static String clipReason(String reason) {
        if (reason == null || reason.length() <= FEDERATION_REASON_MAX) return reason;
        int cut = FEDERATION_REASON_MAX - 1;
        if (Character.isHighSurrogate(reason.charAt(cut - 1))) cut--;
        return reason.substring(0, cut) + "\u2026";
    }

    /** Compare instance domains the way a person types them: trimmed, case-insensitive,
     *  one trailing root dot ignored. {@code null} normalises to "" (never matches a real target). */
    static String normaliseDomain(String domain) {
        if (domain == null) return "";
        String d = domain.trim().toLowerCase(Locale.ROOT);
        return d.endsWith(".") ? d.substring(0, d.length() - 1) : d;
    }

    /**
     * What happened to the federation-api leg of a Matrix instance block. {@code status}:
     * <ul>
     *   <li>{@code filed} — no open row existed; submitted and referred (new id);</li>
     *   <li>{@code referred-existing} — an open {@code recommended} row (e.g. a user's own
     *       recommendation) was referred; its id is reused;</li>
     *   <li>{@code existing} — an open row was already {@code referred}; reused, no write;</li>
     *   <li>{@code unauthorized} — federation-api answered 401 to the moderator's token;</li>
     *   <li>{@code error} — any other failure (non-2xx, timeout, unreachable);</li>
     *   <li>{@code not-configured} — no federation-api client wired (legacy constructor).</li>
     * </ul>
     * {@code moderationRequestId} is kept whenever a row is known to exist, including a
     * submit that succeeded before its refer failed ({@code requestStatus} then says
     * {@code recommended}).
     */
    public record FederationFiling(String status, Long moderationRequestId, String requestStatus,
                                   Integer httpStatus) {

        public static final String FILED = "filed";
        public static final String REFERRED_EXISTING = "referred-existing";
        public static final String EXISTING = "existing";
        public static final String UNAUTHORIZED = "unauthorized";
        public static final String ERROR = "error";
        static final FederationFiling NOT_CONFIGURED = new FederationFiling("not-configured", null, null, null);

        static FederationFiling reused(ModerationRequestDto referred) {
            return new FederationFiling(EXISTING, referred.id(), referred.status(), null);
        }

        static FederationFiling failed(Throwable e, Long knownId) {
            Integer http = e instanceof WebClientResponseException w ? w.getStatusCode().value() : null;
            String status = http != null && http == 401 ? UNAUTHORIZED : ERROR;
            log.warn("[block] federation-api moderation-request leg {} (id={}): {}", status, knownId, e.toString());
            return new FederationFiling(status, knownId, knownId == null ? null : STATUS_RECOMMENDED, http);
        }

        /** The machine-readable {@code federation} object of the block response. */
        Map<String, Object> body() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("status", status);
            out.put("moderationRequestId", moderationRequestId);
            out.put("requestStatus", requestStatus);
            if (httpStatus != null) out.put("httpStatus", httpStatus);
            return out;
        }

        /** The sentence appended to the human {@code note}. */
        String note() {
            return switch (status) {
                case FILED -> " Filed federation moderation request #" + moderationRequestId
                        + " and referred it to administrators for a decision.";
                case REFERRED_EXISTING -> " An open recommendation for this domain already existed (#"
                        + moderationRequestId + "); it has now been referred to administrators.";
                case EXISTING -> " Federation moderation request #" + moderationRequestId
                        + " for this domain is already referred to administrators; nothing new was filed.";
                case UNAUTHORIZED -> " The federation moderation request was NOT filed: federation-api "
                        + "rejected your sign-in token (401). This happens for a moderator signed in through "
                        + "the platform's own login when the Casdoor token exchange failed or is switched off "
                        + "(app.bff-exchange). The block is still recorded here; file it from the moderation "
                        + "queue after signing in through Casdoor."
                        + (moderationRequestId == null ? "" : " Request #" + moderationRequestId
                                + " was created but not referred.");
                case ERROR -> " The federation moderation request could not be completed ("
                        + (httpStatus == null ? "federation-api unreachable or timed out" : "HTTP " + httpStatus)
                        + ")"
                        + (moderationRequestId == null ? "; nothing was filed" : "; request #"
                                + moderationRequestId + " exists but was not referred")
                        + ". The block is still recorded here.";
                default -> " No federation moderation request was filed (federation-api client not configured).";
            };
        }
    }

    /**
     * Decision 51 (operator, 2026-09-18, answer <b>B</b> — AGAINST the "leave deactivate"
     * recommendation): a MOD-initiated Matrix USER block must be REVERSIBLE end to end.
     * tuwunel's only user-block verb is the one-way {@code !admin users deactivate} (no
     * {@code activate} exists), so this never drives a deactivate. Instead it writes the
     * SAME {@code domain_lock} desired-state {@link #domainLock} does (force local-only /
     * no-federation, keyed by {@code ROLE_MATRIX_DOMAINLOCKED}) — which {@code DELETE
     * /bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/{user}} ({@link #domainUnlock}, via
     * {@link AdminDomainLockClient#unlock}) already reverses. <b>This REVERSES decision
     * 5</b> ("ANSWERED 2026-09-10: deactivate", hugmesh-mod-bff-api#1) for the MOD path
     * specifically.
     *
     * <p>The ADMIN-only deactivate lives in hugmesh-admin-bff-api behind a propose/confirm
     * pair (decision 83b, hugmesh-admin-bff-api#115); mod-bff's former copy of the
     * transport ({@code MatrixAdminClient.blockUser}) was deleted (hugmesh-mod-bff-api#23).
     *
     * <p>Bypasses {@link MatrixAdminClient} entirely, so this call is NEVER
     * {@link BlockOutcome#isPosted()} / {@link BlockOutcome#isStubbed()} — only
     * {@link BlockOutcome#DOMAIN_LOCKED} (fresh write; the reconcile loop applies it,
     * never a synchronous "blocked") or {@link BlockOutcome#degraded(String)} (the
     * admin-bff write itself failed — {@link AdminDomainLockClient}'s own circuit
     * breaker fallback, never {@link BlockOutcome#isOk()}).
     */
    private Mono<BlockOutcome> matrixUserBlock(String target, String reason) {
        return domainLocks.lock(AdminDomainLockClient.ROLE_MATRIX_DOMAINLOCKED, target, reason)
                .map(outcome -> outcome.isDegraded()
                        ? BlockOutcome.degraded(outcome.state().substring("degraded:".length()))
                        : BlockOutcome.DOMAIN_LOCKED);
    }

    // ── LIFT (clear access_suspension desired-state) ───────────────────
    /**
     * Lift the ban for {@code target} on {@code platform} (clear the desired-state in
     * admin-bff + record an {@code access.restore} audit row). Same pending-reconcile
     * outcome contract.
     */
    public Mono<BanResult> lift(String platform, String target, String idempotencyKey, Authentication auth) {
        String actor = actor(auth);
        String domain = domain(auth);
        boolean superadmin = Roles.isSuperadmin(auth);
        String role = roleForPlatform(platform);
        // SAME-TENANT guard (fail-closed) before the clear() desired-state write is
        // assembled: a brand-X mod must not lift a brand-Y user's ban any more than
        // they may impose one.
        return guardSameTenant(target, domain, superadmin)
                // Record the deduped audit row and clear (or skip) the desired-state write.
                .then(Mono.defer(() -> recordAndApplyLift(role, platform, target, actor, domain, idempotencyKey)));
    }

    // ── DOMAIN-LOCK (write domain_lock desired-state; ADD-semantics) ───
    /**
     * Domain-lock {@code target} on {@code role} (force their traffic local-only /
     * no-federation). {@code role} is the ADDITIVE marker
     * {@code ROLE_MATRIX_DOMAINLOCKED} | {@code ROLE_MASTODON_DOMAINLOCKED}; the user
     * KEEPS their {@code ROLE_MATRIX}/{@code ROLE_MASTODON} access (the gateway is
     * untouched). Runs the SAME below-them guards as a ban (self → 403; a
     * {@code ROLE_ADMIN}/{@code ROLE_MOD} target → 403), records a DEDUPED audit row,
     * writes the desired-state in admin-bff's SEPARATE {@code domain_lock} table, and
     * returns a pending-reconcile result — never a synchronous "locked", because the
     * reconcile loop applies the {@code ROLE_*_DOMAINLOCKED} marker + the
     * homeserver/egress force-local enforcement. The local row is persisted even if
     * admin-bff is degraded, so the moderator's intent is always auditable.
     */
    public Mono<LockResult> domainLock(String role, String target, String reason,
                                       String idempotencyKey, Authentication auth) {
        String actor = actor(auth);
        String domain = domain(auth);
        boolean superadmin = Roles.isSuperadmin(auth);
        String lockRole = requireDomainLockRole(role);
        return guardNotSelf(actor, target)
                .then(Mono.defer(() -> guardSameTenant(target, domain, superadmin)))
                .then(Mono.defer(() -> guardNotPrivileged(target, domain, superadmin)))
                // Record the deduped audit row and apply (or skip) the domain-lock desired-state write.
                .then(Mono.defer(() -> recordAndApplyLock(lockRole, target, reason, actor, domain, idempotencyKey)));
    }

    /**
     * Domain-UNLOCK {@code target} on {@code role} (clear the {@code domain_lock}
     * desired-state + record a {@code domain.unlock} audit row). The reconcile loop
     * drops the {@code ROLE_*_DOMAINLOCKED} marker + stops gating on the next tick.
     * Same below-them guards + pending-reconcile outcome contract as {@link #domainLock}.
     */
    public Mono<LockResult> domainUnlock(String role, String target, String idempotencyKey, Authentication auth) {
        String actor = actor(auth);
        String domain = domain(auth);
        boolean superadmin = Roles.isSuperadmin(auth);
        String lockRole = requireDomainLockRole(role);
        return guardNotSelf(actor, target)
                .then(Mono.defer(() -> guardSameTenant(target, domain, superadmin)))
                .then(Mono.defer(() -> guardNotPrivileged(target, domain, superadmin)))
                // Record the deduped audit row and apply (or skip) the domain-unlock desired-state write.
                .then(Mono.defer(() -> recordAndApplyUnlock(lockRole, target, actor, domain, idempotencyKey)));
    }

    /**
     * Validate the domain-lock MARKER role and return it unchanged: admin-bff keys its
     * {@code domain_lock} surface by the role itself ({@code ROLE_MATRIX_DOMAINLOCKED} |
     * {@code ROLE_MASTODON_DOMAINLOCKED}), NOT by a {@code matrix|mastodon} platform name
     * (a platform name in that path segment is a 400 there, hugmesh-mod-bff-api#26). Any
     * other value is a 400 here (the controller also {@code @Pattern}s the path variable to
     * exactly these two roles — defence in depth).
     */
    static String requireDomainLockRole(String role) {
        return switch (role == null ? "" : role) {
            case AdminDomainLockClient.ROLE_MATRIX_DOMAINLOCKED,
                 AdminDomainLockClient.ROLE_MASTODON_DOMAINLOCKED -> role;
            default -> throw ApiException.badRequest("unknown domain-lock role: " + role);
        };
    }

    // ── Platform-role re-check for the server-wide block surface ───────
    /**
     * Service-layer re-check of the platform-role assertion the controller also makes
     * with {@code @PreAuthorize}: a {@code matrix} block requires {@code ROLE_MATRIX}
     * (or {@code ROLE_ADMIN}); {@code mastodon} requires {@code ROLE_MASTODON} (or
     * {@code ROLE_ADMIN}). Throws a 403 {@link ApiException} otherwise. Called from
     * {@code ModController.block()} BEFORE any homeserver/audit effect.
     */
    public void assertPlatformRole(String platform, Authentication auth) {
        if (hasRole(auth, "ROLE_ADMIN")) return;
        // Route the closed matrix|mastodon vocabulary through PlatformKind (same lowercase
        // tokens). A null/unrecognised platform (or 'profile', which the block surface
        // never reaches) yields a null required-role → no extra platform-role gate, exactly
        // the prior 'default -> null' fall-through.
        String required = switch (PlatformKind.fromWire(platform)) {
            case MATRIX   -> "ROLE_MATRIX";
            case MASTODON -> "ROLE_MASTODON";
            case null, default -> null;
        };
        if (required != null && !hasRole(auth, required)) {
            throw ApiException.forbidden("platform '" + platform + "' requires " + required + " (or ROLE_ADMIN)");
        }
    }

    // ── Server-wide block (external homeserver admin + local audit) ────
    /**
     * Block a {@code target} (user or instance) server-wide on {@code platform}
     * ({@code matrix}/{@code mastodon}). The block surface previously ran ONLY the
     * platform-role assertion and SKIPPED the below-them / cross-tenant guards that
     * {@link #ban}/{@link #lift}/{@link #domainLock} all enforce — a brand-X MOD could
     * block a brand-Y user or a privileged ({@code ROLE_ADMIN}/{@code ROLE_MOD}) target.
     * This method closes that gap: it runs the SAME guards in the SAME order as a ban —
     * {@code guardNotSelf} → {@code guardSameTenant} → {@code guardNotPrivileged} — and
     * the platform-role assertion, ALL BEFORE any external homeserver call or audit row
     * is touched. Only once every guard passes is the (STUBBED) homeserver admin call
     * made and the action recorded in {@code mod_action}, stamped with the caller's
     * issuer-derived {@code domain} so the brand's scoped audit read can see it.
     *
     * @return the persisted audit row + the external {@link BlockOutcome}; the controller
     *         maps a non-OK outcome to {@code 202 pending-reconcile} (never a 200).
     */
    public Mono<BlockResult> block(String platform, String scope, String target, String reason,
                                   Authentication auth) {
        String actor = actor(auth);
        String domain = domain(auth);
        boolean superadmin = Roles.isSuperadmin(auth);
        // Route the closed user|instance scope through ScopeKind (same lowercase token):
        // USER → the user-block leg, any non-USER value (instance) → the instance leg —
        // identical to the prior `"user".equals(scope)` boolean.
        boolean user = ScopeKind.USER == ScopeKind.fromWire(scope);
        // SAME guards as a ban, in the SAME order, ALL BEFORE the platform-role assertion
        // AND before any external/audit effect: a self-target, a cross-tenant target, or a
        // privileged (ROLE_ADMIN/ROLE_MOD) target is denied 403 and NO homeserver call or
        // audit row is ever made. guardSameTenant/guardNotPrivileged are deferred so the
        // Casdoor round-trips only run once the cheap self-guard passes.
        return guardNotSelf(actor, target)
                .then(Mono.defer(() -> guardSameTenant(target, domain, superadmin)))
                .then(Mono.defer(() -> guardNotPrivileged(target, domain, superadmin)))
                // Assert platform role then dispatch the external homeserver call and record the audit row.
                .then(Mono.defer(() -> assertAndApplyBlock(platform, target, reason, actor, domain, user, auth)));
    }

    // ── OWNCAST live-stream moderation (owncast-bff effector + central ledger row) ──
    /**
     * HIDE the target owner's owncast stream (force {@code visibility=internal}) via
     * owncast-bff's moderation surface, and record an {@code owncast.hide} row in the
     * central ledger. Runs the SAME punitive-action guards as a ban/block —
     * {@code guardNotSelf} → {@code guardSameTenant} → {@code guardNotPrivileged} —
     * ALL BEFORE the effector call or ledger row. UNLIKE the admin-bff desired-state
     * writers the owncast effect is SYNCHRONOUS: an OK outcome means the hide already
     * landed (controller returns 200 applied); a degraded owncast-bff yields
     * {@code degraded:<reason>} — recorded honestly on the ledger row, surfaced as
     * 202 not-applied, NEVER a fake success (there is NO reconcile loop here).
     */
    public Mono<OwncastModResult> owncastHide(String target, String reason, Authentication auth) {
        return owncastModerate(ModActionType.OWNCAST_HIDE, target, reason, true, auth);
    }

    /**
     * KILL the target owner (owncast-bff writes an active {@code owncast_grant(banned)}
     * + hides the stream) and record an {@code owncast.kill} ledger row. Same guards +
     * synchronous-outcome contract as {@link #owncastHide}.
     */
    public Mono<OwncastModResult> owncastKill(String target, String reason, Authentication auth) {
        return owncastModerate(ModActionType.OWNCAST_KILL, target, reason, true, auth);
    }

    /**
     * RESTORE the target owner (owncast-bff CASes the active broadcast ban
     * active→revoked; no auto-republish) and record an {@code owncast.restore} ledger
     * row. REMEDIAL — mirrors {@link #lift}: only the cross-tenant guard applies (no
     * self/privileged guard on a restorative action).
     */
    public Mono<OwncastModResult> owncastRestore(String target, String reason, Authentication auth) {
        return owncastModerate(ModActionType.OWNCAST_RESTORE, target, reason, false, auth);
    }

    /**
     * Shared owncast moderation flow: guards (punitive actions get the full
     * self/tenant/privileged chain, remedial ones the tenant proof only — the same
     * split ban-vs-lift uses), then the effector call, then the ledger row recording
     * the HONEST outcome. Guard order and deferral mirror {@link #block}.
     */
    private Mono<OwncastModResult> owncastModerate(String action, String target, String reason,
                                                   boolean punitive, Authentication auth) {
        String actor = actor(auth);
        String domain = domain(auth);
        boolean superadmin = Roles.isSuperadmin(auth);
        Mono<Void> guards = punitive
                ? guardNotSelf(actor, target)
                        .then(Mono.defer(() -> guardSameTenant(target, domain, superadmin)))
                        .then(Mono.defer(() -> guardNotPrivileged(target, domain, superadmin)))
                : guardSameTenant(target, domain, superadmin);
        // Only once every guard passes is the owncast-bff effector called and the
        // central ledger row written (with the caller's issuer-derived domain stamp).
        return guards.then(Mono.defer(() -> applyOwncast(action, target, reason, actor, domain)));
    }

    /**
     * Dispatch the owncast-bff effector call for {@code action} and record the ledger
     * row AFTER the outcome resolves (mirrors {@link #assertAndApplyBlock}): the row's
     * {@code result} column carries the honest {@code ok} / {@code degraded:<reason>}
     * outcome. A 404 (no stream in the brand) errors BEFORE any row is written — no
     * action happened, so nothing is ledgered.
     */
    private Mono<OwncastModResult> applyOwncast(String action, String target, String reason,
                                                String actor, String domain) {
        Mono<BlockOutcome> external = switch (action) {
            case ModActionType.OWNCAST_HIDE -> owncast.hide(target, reason);
            case ModActionType.OWNCAST_KILL -> owncast.kill(target, reason);
            default                         -> owncast.restore(target, reason);
        };
        return external.flatMap(outcome -> audit.record(actor, action, "owncast", target,
                        reason, outcome.result(), domain)
                .map(recorded -> new OwncastModResult(recorded, outcome)));
    }

    // ── TUBE moderation (TubeModClient effector + central ledger row) ──
    /**
     * HIDE the target owner's tube content and record a {@code tube.hide} row in the
     * central ledger. The caller must be a tube moderator ({@link Roles#isTubeMod}: MOD
     * and TUBE), checked FIRST; then the punitive-action guards run ({@code guardNotSelf}
     * &rarr; {@code guardSameTenant} &rarr; {@code guardNotPrivileged}), all BEFORE the
     * effector call or ledger row. With no {@link TubeModClient} registered nothing runs
     * and nothing is ledgered. The ledger row records the HONEST effector outcome
     * ({@code ok} / {@code degraded:<reason>}); an effector error (e.g. no such content)
     * writes no row.
     */
    public Mono<TubeModResult> tubeHide(String target, String reason, Authentication auth) {
        if (!Roles.isTubeMod(auth)) {
            return Mono.error(ApiException.forbidden("tube moderation requires ROLE_MOD and ROLE_TUBE"));
        }
        if (tube == null) {
            return Mono.error(new IllegalStateException("tube moderation is not configured"));
        }
        String actor = actor(auth);
        String domain = domain(auth);
        boolean superadmin = Roles.isSuperadmin(auth);
        return guardNotSelf(actor, target)
                .then(Mono.defer(() -> guardSameTenant(target, domain, superadmin)))
                .then(Mono.defer(() -> guardNotPrivileged(target, domain, superadmin)))
                .then(Mono.defer(() -> tube.hide(target, reason)))
                .flatMap(outcome -> audit.record(actor, ModActionType.TUBE_HIDE, "tube", target,
                                reason, outcome.result(), domain)
                        .map(recorded -> new TubeModResult(recorded, outcome)));
    }

    private static String blockActionFor(String platform, boolean user) {
        // matrix → the matrix.block-* verb; anything else (mastodon, the only other value the
        // BlockRequest @Pattern permits) → the mastodon.block-* verb — identical to the prior
        // `"matrix".equals(platform)` branch, now keyed off PlatformKind.MATRIX.
        if (PlatformKind.MATRIX == PlatformKind.fromWire(platform)) {
            return user ? ModActionType.MATRIX_BLOCK_USER : ModActionType.MATRIX_BLOCK_INSTANCE;
        }
        return user ? ModActionType.MASTODON_BLOCK_USER : ModActionType.MASTODON_BLOCK_INSTANCE;
    }

    // ── Guards ─────────────────────────────────────────────────────────
    private Mono<Void> guardNotSelf(String actor, String target) {
        if (actor != null && actor.equalsIgnoreCase(target)) {
            return Mono.error(ApiException.forbidden("a moderator may not ban themselves"));
        }
        return Mono.empty();
    }

    /**
     * CROSS-DOMAIN guard (the A01 BOLA/BFLA fix). Before ANY ban/lock/lift/unlock write
     * effect is assembled, prove the {@code target} belongs to the CALLER's tenant —
     * resolved AUTHORITATIVELY from the caller's per-domain Casdoor org
     * ({@link CasdoorRoleClient#belongsToDomain}). The branched bypasses mirror
     * {@link Roles#domainApplies(String, String, boolean)} exactly:
     * <ul>
     *   <li>SUPERADMIN (the cross-domain infra control plane) — bypass (its leg of
     *       {@code domainApplies} is always true); legitimate cross-brand moderation is
     *       preserved;</li>
     *   <li>a {@code null}/blank/{@code "default"} caller domain — the single-tenant inert
     *       domain ({@code domainApplies}'s global/unscoped leg): one Casdoor org, no
     *       second tenant to cross into, so the guard is a no-op and the single-tenant /
     *       Casdoor-less dev flow is unchanged;</li>
     *   <li>otherwise a BRANDED caller — the target MUST be a proven member of the
     *       caller's brand org.</li>
     * </ul>
     *
     * <p>FAIL-CLOSED: a branded caller's check short-circuits with a 403 (via
     * {@code switchIfEmpty} on an empty/false membership) so the
     * suspend()/lock()/clear() write is NEVER reached for a target whose domain cannot be
     * PROVEN equal to the caller's (a cross-brand target, an absent target, or an
     * unreachable/disabled Casdoor all resolve false → deny).
     */
    private Mono<Void> guardSameTenant(String target, String callerDomain, boolean superadmin) {
        // SUPERADMIN (the cross-domain infra control plane) sees every brand — no
        // per-target tenant proof required, matching Roles.domainApplies's superadmin leg.
        if (superadmin) return Mono.empty();
        // SINGLE-TENANT inert domain: a null/blank/'default' caller domain means the
        // cluster is NOT in multi-brand mode (one Casdoor org, one domain), so there is
        // no other tenant to cross INTO and no cross-tenant attack surface — the guard is
        // a no-op (and a Casdoor-less dev/CI run keeps booting + banning clean). The
        // cross-domain BFLA only exists once the caller carries a real DOMAIN_<brand>.
        if (callerDomain == null || callerDomain.isBlank()
                || DomainRegistry.DEFAULT_DOMAIN.equalsIgnoreCase(callerDomain)) {
            return Mono.empty();
        }
        // BRANDED caller: belongsToDomain resolves the target's brand AUTHORITATIVELY
        // against the caller's per-domain Casdoor org — a target in another brand's org
        // (or unprovable) yields false → switchIfEmpty 403, fail-closed, BEFORE any
        // suspend()/lock()/clear() write is assembled.
        return roles.belongsToDomain(target, callerDomain)
                .filter(Boolean::booleanValue)
                .switchIfEmpty(Mono.error(ApiException.forbidden(
                        "target is not in the moderator's domain and cannot be moderated cross-tenant")))
                .then();
    }

    /**
     * BELOW-THEM guard: a MOD may not ban/lock a PRIVILEGED target
     * ({@code ROLE_ADMIN}/{@code ROLE_MOD}). The {@code superadmin} bypass mirrors
     * {@link #guardSameTenant}'s superadmin leg (and {@link Roles#domainApplies}): a
     * SUPERADMIN is the cross-domain infra control plane that sits ABOVE the ADMIN/MOD
     * tier in the role hierarchy ({@code ROLE_SUPERADMIN > ROLE_ADMIN}, PR #52), so it is
     * not bounded by the privileged-target restriction — the ban/lock/unlock/block WRITE
     * proceeds. Without this bypass a branded superadmin (whose real {@code DOMAIN_<x>}
     * makes {@link CasdoorRoleClient#isPrivileged} fail closed on the disabled test-seam)
     * was wrongly 403'd, contradicting the post-#52 hierarchy model the boot test asserts.
     */
    private Mono<Void> guardNotPrivileged(String target, String callerDomain, boolean superadmin) {
        // SUPERADMIN (cross-domain infra control plane, above the ADMIN/MOD tier) is not
        // bounded by the below-them privileged-target guard — matching guardSameTenant.
        if (superadmin) return Mono.empty();
        return roles.isPrivileged(target, callerDomain).flatMap(privileged -> privileged
                ? Mono.error(ApiException.forbidden(
                        "target holds ROLE_ADMIN or ROLE_MOD and cannot be banned by a moderator"))
                : Mono.empty());
    }

    // ── Mapping helpers ────────────────────────────────────────────────
    static String roleForPlatform(String platform) {
        // Lower-case FIRST (the ban path is case-insensitive, matching the BanRequest
        // (?i)matrix|mastodon|profile @Pattern), then route the now-canonical token through
        // PlatformKind. An unknown/null token (null kind) is still a 400 — identical to the
        // prior 'default -> throw badRequest' leg.
        PlatformKind kind = PlatformKind.fromWire(platform == null ? null : platform.toLowerCase());
        return switch (kind) {
            case MATRIX   -> "ROLE_MATRIX";
            case MASTODON -> "ROLE_MASTODON";
            case PROFILE  -> "PROFILE";
            case null     -> throw ApiException.badRequest("unknown ban platform: " + platform);
        };
    }

    private static String banType(String platform) {
        return "profile".equalsIgnoreCase(platform) ? "profile" : "user";
    }

    private static boolean hasRole(Authentication auth, String role) {
        if (auth == null) return false;
        for (GrantedAuthority a : auth.getAuthorities()) {
            if (role.equals(a.getAuthority())) return true;
        }
        return false;
    }

    private static String actor(Authentication auth) {
        return auth == null ? "mod" : auth.getName();
    }

    /** The acting moderator's brand/domain for the audit-row stamp — read off the
     *  VALIDATED {@code DOMAIN_<x>} authority the converter emits from the token issuer,
     *  NEVER a user-settable claim. A {@code null} (zero or &gt;1 DOMAIN_ — the
     *  fail-closed/injection signal from {@link Roles#domainOf(Authentication)}) falls
     *  back to {@code "default"} so the WRITE is always scoped to a concrete tenant (the
     *  legacy single-tenant domain) and never violates the NOT NULL column; the
     *  domain-scoped READS apply the same fail-closed null contract on their side. */
    public static String domain(Authentication auth) {
        String d = Roles.domainOf(auth);
        return d == null ? DomainRegistry.DEFAULT_DOMAIN : d;
    }

    /** The pending-reconcile outcome of a ban/lift + the persisted audit row. */
    public record BanResult(ModAction action, String state, boolean deduped) {

        static BanResult pending(ModAction action, boolean deduped) {
            return new BanResult(action, SuspensionOutcome.PENDING.state(), deduped);
        }

        static BanResult of(ModAction action, SuspensionOutcome outcome, boolean deduped) {
            return new BanResult(action, outcome.state(), deduped);
        }

        /** The 202 body the controller returns. */
        public Map<String, Object> body() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("state", "pending-reconcile");
            out.put("propagation", state);
            out.put("deduped", deduped);
            out.put("action", action);
            return out;
        }
    }

    /**
     * The pending-reconcile outcome of a domain-lock/unlock + the persisted audit row.
     * Identical shape to {@link BanResult} (the reconcile loop owns the real effect), so
     * the controller returns the same {@code 202 {state:'pending-reconcile'}} contract.
     */
    public record LockResult(ModAction action, String state, boolean deduped) {

        static LockResult pending(ModAction action, boolean deduped) {
            return new LockResult(action, SuspensionOutcome.PENDING.state(), deduped);
        }

        static LockResult of(ModAction action, SuspensionOutcome outcome, boolean deduped) {
            return new LockResult(action, outcome.state(), deduped);
        }

        /** The 202 body the controller returns. */
        public Map<String, Object> body() {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("state", "pending-reconcile");
            out.put("propagation", state);
            out.put("deduped", deduped);
            out.put("action", action);
            return out;
        }
    }

    /**
     * The outcome of a server-wide block + the persisted audit row. The controller maps
     * this to the HTTP body: a real {@link BlockOutcome#isOk()} returns {@code 200 blocked};
     * a STUBBED / degraded / breaker-open outcome did NOT land the homeserver effect so it
     * returns {@code 202 pending-reconcile}.
     */
    public record BlockResult(ModAction action, BlockOutcome outcome, FederationFiling federation) {

        /** A block with no federation-api leg (every block except a Matrix instance block). */
        public BlockResult(ModAction action, BlockOutcome outcome) {
            this(action, outcome, null);
        }

        /** The HTTP body the controller returns (200 when applied, else 202 pending).
         *  {@code moderationRequestId} (decision 84d) is always present — the federation-api
         *  {@code moderation_requests} id, or {@code null} when no row exists; a Matrix
         *  instance block additionally carries the {@code federation} leg's outcome. */
        public Map<String, Object> body() {
            boolean applied = outcome.isOk();
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("state", applied ? "blocked" : "pending-reconcile");
            out.put("external", outcome.result());
            out.put("blocked", action);
            out.put("moderationRequestId", federation == null ? null : federation.moderationRequestId());
            if (federation != null) {
                out.put("federation", federation.body());
            }
            if (outcome.isStubbed()) {
                // With a federation leg the row is NOT local-only — the federation sentence
                // appended below says where it went, so the prose must not contradict it.
                out.put("note", "external homeserver admin call is STUBBED (integration disabled) — "
                        + (federation == null ? "action recorded in the local audit table only; " : "")
                        + "no homeserver effect was applied");
            } else if (outcome.isPosted()) {
                out.put("note", "deactivate command posted to the tuwunel admin room (" + outcome.result()
                        + ") — the admin bot applies it asynchronously and its reply is not yet correlated; "
                        + "treat as pending until confirmed on the homeserver");
            } else if (outcome.isDomainLocked()) {
                out.put("note", "applied as a REVERSIBLE domain-lock (forced local-only / no-federation), "
                        + "not the homeserver's one-way deactivate — lift with DELETE "
                        + "/bff/mod/domain-lock/ROLE_MATRIX_DOMAINLOCKED/{user} (operator decision 51, "
                        + "2026-09-18; reverses decision 5's \"deactivate\")");
            } else if (outcome.isRequested()) {
                out.put("note", "recorded as a REQUEST, not applied: tuwunel exposes no runtime "
                        + "per-server federation-block verb, so a real instance block needs a "
                        + "forbidden_remote_server_names config edit, a GitOps reconcile, and a homeserver "
                        + "restart. This mod_action row is the durable, visible record of the request; "
                        + "requested, applied by an administrator (operator decision 50, 2026-09-18)");
            }
            if (federation != null) {
                out.merge("note", federation.note().trim(), (prior, extra) -> prior + " " + extra);
            }
            return out;
        }
    }

    /**
     * The outcome of an owncast hide/kill/restore + the persisted central-ledger row.
     * The owncast-bff effect is SYNCHRONOUS (unlike the reconcile-loop surfaces): an
     * {@link BlockOutcome#isOk() ok} outcome means the effect ALREADY landed → the
     * controller returns {@code 200 {state:'applied'}}. A degraded outcome means it
     * did NOT land and there is NO reconcile loop to converge it later — the body says
     * so explicitly ({@code state:'not-applied'} + a retry note), never a fake success.
     */
    public record OwncastModResult(ModAction action, BlockOutcome outcome) {

        /** The HTTP body the controller returns (200 applied, else 202 not-applied). */
        public Map<String, Object> body() {
            boolean applied = outcome.isOk();
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("state", applied ? "applied" : "not-applied");
            out.put("external", outcome.result());
            out.put("action", action);
            if (!applied) {
                out.put("note", "owncast-bff moderation call did not land (" + outcome.result()
                        + ") — the intent is recorded in the central mod_action ledger, but there is "
                        + "NO reconcile loop on this surface: retry once owncast-bff is healthy");
            }
            return out;
        }
    }

    /** The outcome of a tube hide + the persisted central-ledger row. Like the owncast
     *  effect it is SYNCHRONOUS: only an {@link BlockOutcome#isOk() ok} outcome is applied. */
    public record TubeModResult(ModAction action, BlockOutcome outcome) {

        public boolean applied() {
            return outcome.isOk();
        }
    }
}
