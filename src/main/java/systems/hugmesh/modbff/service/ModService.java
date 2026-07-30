package systems.hugmesh.modbff.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;
import systems.hugmesh.modbff.admin.AdminDomainLockClient;
import systems.hugmesh.modbff.admin.AdminSuspensionClient;
import systems.hugmesh.modbff.admin.CasdoorRoleClient;
import systems.hugmesh.modbff.admin.SuspensionOutcome;
import systems.hugmesh.modbff.audit.ModAction;
import systems.hugmesh.modbff.audit.ModActionKey;
import systems.hugmesh.modbff.audit.ModActionRepository;
import systems.hugmesh.modbff.audit.ModActionType;
import systems.hugmesh.modbff.external.BlockOutcome;
import systems.hugmesh.modbff.external.MastodonAdminClient;
import systems.hugmesh.modbff.external.MatrixAdminClient;
import systems.hugmesh.modbff.model.PlatformKind;
import systems.hugmesh.modbff.model.ScopeKind;
import systems.hugmesh.modbff.notify.NotifyDirective;
import systems.hugmesh.modbff.owncast.OwncastModClient;
import systems.hugmesh.commons.security.DomainRegistry;
import systems.hugmesh.modbff.security.Roles;
import systems.hugmesh.commons.web.ApiException;

import java.time.LocalDateTime;
import java.util.LinkedHashMap;
import java.util.List;
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

    public ModService(AdminSuspensionClient suspensions, AdminDomainLockClient domainLocks,
                      CasdoorRoleClient roles, ModActionRepository audit,
                      MatrixAdminClient matrix, MastodonAdminClient mastodon,
                      OwncastModClient owncast) {
        this.suspensions = suspensions;
        this.domainLocks = domainLocks;
        this.roles = roles;
        this.audit = audit;
        this.matrix = matrix;
        this.mastodon = mastodon;
        this.owncast = owncast;
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
    private Mono<LockResult> recordAndApplyLock(String role, String platform, String target,
                                                String reason, String actor, String domain, String idempotencyKey) {
        // Build a dedup key scoped to this actor, target, domain, and idempotency token.
        String dedupKey = ModActionKey.ban(ModActionType.DOMAIN_LOCK, role, target, actor, domain, idempotencyKey);
        // Record the domain-lock intent (idempotent on dedup_key) before any desired-state write.
        return audit.recordBan(dedupKey, actor, ModActionType.DOMAIN_LOCK, "domain-lock",
                        target, reason, "user", null, "pending", domain)
                // Delegate the fresh-vs-dedup decision and the actual lock write to a named helper.
                .flatMap(recorded -> applyLockOrDedup(recorded, role, platform, target, reason));
    }

    /**
     * Decide whether the domain-lock desired-state write should be issued (fresh row) or
     * skipped (dedup hit on an already-recorded intent row). Extracted to keep the
     * recordAndApplyLock flatMap body within the 10-line Checkstyle limit.
     */
    private Mono<LockResult> applyLockOrDedup(ModActionRepository.RecordedBan recorded,
                                              String role, String platform, String target, String reason) {
        // Dedup hit: the lock() was already issued; return the persisted pending row.
        if (!recorded.fresh()) {
            log.info("[domain-lock] dedup hit — role={} target={} already recorded (id={})",
                    role, target, recorded.action().id());
            return Mono.just(LockResult.pending(recorded.action(), true));
        }
        // Fresh row: forward the lock desired-state to admin-bff and map the outcome.
        return domainLocks.lock(platform, target, reason)
                .map(outcome -> LockResult.of(recorded.action(), outcome, false));
    }

    /**
     * Build the dedup key, record the domain-unlock row, and then either skip (dedup hit)
     * or call unlock() to forward the desired-state to admin-bff.
     */
    private Mono<LockResult> recordAndApplyUnlock(String role, String platform, String target,
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
                    return domainLocks.unlock(platform, target)
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
        Mono<BlockOutcome> external = switch (PlatformKind.fromWire(platform)) {
            case MATRIX   -> user ? matrix.blockUser(target)   : matrix.blockInstance(target);
            case MASTODON -> user ? mastodon.blockUser(target) : mastodon.blockInstance(target);
            case null, default -> Mono.just(BlockOutcome.STUBBED);
        };
        String action = blockActionFor(platform, user);
        // Record the audit row after the external call resolves, then wrap into BlockResult.
        return external.flatMap(outcome -> audit.record(actor, action, platform, target,
                        reason, outcome.result(), domain)
                .map(recorded -> new BlockResult(recorded, outcome)));
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
        String platform = platformForDomainLockRole(role);
        return guardNotSelf(actor, target)
                .then(Mono.defer(() -> guardSameTenant(target, domain, superadmin)))
                .then(Mono.defer(() -> guardNotPrivileged(target, domain, superadmin)))
                // Record the deduped audit row and apply (or skip) the domain-lock desired-state write.
                .then(Mono.defer(() -> recordAndApplyLock(role, platform, target, reason, actor, domain, idempotencyKey)));
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
        String platform = platformForDomainLockRole(role);
        return guardNotSelf(actor, target)
                .then(Mono.defer(() -> guardSameTenant(target, domain, superadmin)))
                .then(Mono.defer(() -> guardNotPrivileged(target, domain, superadmin)))
                // Record the deduped audit row and apply (or skip) the domain-unlock desired-state write.
                .then(Mono.defer(() -> recordAndApplyUnlock(role, platform, target, actor, domain, idempotencyKey)));
    }

    /**
     * Map the domain-lock MARKER role to the admin-bff domain-lock PLATFORM key.
     * {@code ROLE_MATRIX_DOMAINLOCKED}→{@code matrix}, {@code ROLE_MASTODON_DOMAINLOCKED}
     * →{@code mastodon}. Any other value is a 400 (the controller also {@code @Pattern}s
     * the path variable to exactly these two roles — defence in depth).
     */
    static String platformForDomainLockRole(String role) {
        return switch (role == null ? "" : role) {
            case "ROLE_MATRIX_DOMAINLOCKED"   -> "matrix";
            case "ROLE_MASTODON_DOMAINLOCKED" -> "mastodon";
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
    public record BlockResult(ModAction action, BlockOutcome outcome) {

        /** The HTTP body the controller returns (200 when applied, else 202 pending). */
        public Map<String, Object> body() {
            boolean applied = outcome.isOk();
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("state", applied ? "blocked" : "pending-reconcile");
            out.put("external", outcome.result());
            out.put("blocked", action);
            if (outcome.isStubbed()) {
                out.put("note", "external homeserver admin call is STUBBED (unconfirmed admin shape) — "
                        + "action recorded in the local audit table only; reconcile applies the real effect");
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
}
