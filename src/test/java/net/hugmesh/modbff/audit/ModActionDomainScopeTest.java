package net.hugmesh.modbff.audit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.modbff.support.PostgresSliceTestConfig;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DOMAIN-SCOPING of the audit trail at the R2DBC layer — the multi-tenant ISOLATION
 * BOUNDARY (the security keystone of the foundation-auth work), over the REAL Liquibase
 * schema (the {@code domain} column from changelog 005). Delineated per the test
 * standard:
 *
 * <ul>
 *   <li>USER-SITUATIONAL — a single brand's rows round-trip, stamped with its domain;
 *       a domain-less write defaults to {@code "default"} (never un-scoped).</li>
 *   <li>MULTIUSER-SITUATIONAL — two brands' rows coexist; each scoped read returns only
 *       its own.</li>
 *   <li>CROSS-USER — the NEGATIVE isolation: a brand-X-scoped read NEVER returns
 *       brand-Y's rows; a {@code null}/ambiguous domain fails CLOSED (empty); the
 *       unscoped {@code list()} (SUPERADMIN) sees BOTH brands.</li>
 *   <li>CONCURRENT — interleaved writes from two brands stay correctly partitioned;
 *       concurrent scoped reads never leak across the boundary.</li>
 * </ul>
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, ModActionRepository.class})
// PostgresTestSupport gives this class its OWN fresh container db (no rows shared with
// the sibling audit slices), so the former @TestPropertySource separate-context hack the
// H2 slices used is no longer needed. Moved off H2 because the shared changelog now applies
// the DB-generated-id 009 (pgcrypto/gen_random_uuid()) that H2 cannot run.
class ModActionDomainScopeTest extends PostgresTestSupport {

    @Autowired ModActionRepository repo;
    @Autowired DatabaseClient db;

    /** Each method starts from an empty table so the per-domain COUNT assertions are
     *  exact (this class's methods otherwise share one H2 mem store). */
    @BeforeEach
    void clean() {
        db.sql("DELETE FROM mod_action").fetch().rowsUpdated().block();
    }

    private Mono<ModAction> banRow(String dedup, String actor, String target, String domain) {
        return repo.recordBan(dedup, actor, ModActionType.ACCESS_SUSPEND, "access",
                        target, "abuse", "user", null, "pending", domain)
                .map(ModActionRepository.RecordedBan::action);
    }

    // ── USER-SITUATIONAL ──────────────────────────────────────────────────────

    @Test
    void recordStampsDomain_andScopedReadReturnsIt() {
        StepVerifier.create(repo.record("mod:bob", ModActionType.MATRIX_BLOCK_USER, "matrix",
                        "@spam:evil.example", "abuse", "stubbed", "brandx"))
                .assertNext(a -> assertThat(a.domain()).isEqualTo("brandx"))
                .verifyComplete();

        StepVerifier.create(repo.listForDomain("brandx"))
                .assertNext(a -> assertThat(a.domain()).isEqualTo("brandx"))
                .verifyComplete();
    }

    @Test
    void domainlessWrite_defaultsToDefault_neverUnscoped() {
        // A write with a null/blank domain stamps "default" (the legacy single-tenant
        // domain) so a row is never un-scoped/invisible.
        repo.record("mod:bob", ModActionType.FEDERATION_REFER, "federation",
                "moderation-request:1", null, "ok", null).block();
        repo.record("mod:bob", ModActionType.FEDERATION_REFER, "federation",
                "moderation-request:2", null, "ok", "  ").block();
        StepVerifier.create(repo.listForDomain("default").collectList())
                .assertNext(rows -> assertThat(rows).hasSize(2)
                        .allSatisfy(a -> assertThat(a.domain()).isEqualTo("default")))
                .verifyComplete();
    }

    // ── MULTIUSER-SITUATIONAL ─────────────────────────────────────────────────

    @Test
    void twoBrandsCoexist_eachScopedReadSeesOnlyItsOwn() {
        banRow("x-1", "mod:x", "alice", "brandx").block();
        banRow("x-2", "mod:x", "bob", "brandx").block();
        banRow("y-1", "mod:y", "carol", "brandy").block();

        StepVerifier.create(repo.listForDomain("brandx").collectList())
                .assertNext(rows -> assertThat(rows).hasSize(2)
                        .allSatisfy(a -> assertThat(a.domain()).isEqualTo("brandx")))
                .verifyComplete();
        StepVerifier.create(repo.listForDomain("brandy").collectList())
                .assertNext(rows -> assertThat(rows).hasSize(1)
                        .allSatisfy(a -> assertThat(a.domain()).isEqualTo("brandy")))
                .verifyComplete();
    }

    // ── CROSS-USER — the isolation boundary ───────────────────────────────────

    @Test
    void brandXScopedRead_neverReturnsBrandYRows() {
        banRow("x-1", "mod:x", "alice", "brandx").block();
        banRow("y-1", "mod:y", "alice", "brandy").block();   // SAME target, OTHER brand

        // NEGATIVE isolation: a brand-X read must NEVER surface brand-Y's row, even for
        // the same target name.
        StepVerifier.create(repo.listForDomain("brandx").collectList())
                .assertNext(rows -> assertThat(rows)
                        .extracting(ModAction::domain).containsOnly("brandx"))
                .verifyComplete();
    }

    @Test
    void scopedReadByActor_isAlsoDomainBounded() {
        // Same actor name acting in two brands — the actor-scoped read must still be
        // domain-bounded (a brand-X audit of "mod:shared" never shows brand-Y rows).
        banRow("x-1", "mod:shared", "alice", "brandx").block();
        banRow("y-1", "mod:shared", "bob", "brandy").block();

        StepVerifier.create(repo.listByActorForDomain("mod:shared", "brandx").collectList())
                .assertNext(rows -> assertThat(rows).hasSize(1)
                        .allSatisfy(a -> {
                            assertThat(a.domain()).isEqualTo("brandx");
                            assertThat(a.target()).isEqualTo("alice");
                        }))
                .verifyComplete();
    }

    /**
     * CROSS-USER — the cross-tenant DEDUP-COLLISION regression (the gap this changeset
     * closes). Two brands whose Casdoor mint the SAME actor-subject string ("alice")
     * ban the SAME target+role with NO client idempotency token. Pre-fix the dedup key
     * was {@code sha256(action|role|target|actor|idem)} with no domain — identical for
     * both brands — and the uniqueness was GLOBAL on dedup_key, so brand-Y's recordBan
     * hit ON CONFLICT DO NOTHING against brand-X's row and the read-back LEAKED brand-X's
     * row (wrong domain) into brand-Y AND reported fresh=false (swallowing brand-Y's
     * effect). Post-fix: the domain is in the key (distinct keys) AND the composite
     * (dedup_key, domain) uniqueness AND the domain-scoped read-back, so each brand gets
     * its OWN fresh row scoped to its OWN domain.
     */
    @Test
    void sameActorSubject_twoBrands_noIdempotencyKey_doNotCollide() {
        String actor = "alice";          // SAME subject string minted by BOTH brands' Casdoor
        String target = "victim";
        String role = "ROLE_MATRIX";

        // The key now carries the domain, so the two brands' keys DIFFER.
        String keyX = ModActionKey.ban(ModActionType.ACCESS_SUSPEND, role, target, actor, "brandx", null);
        String keyY = ModActionKey.ban(ModActionType.ACCESS_SUSPEND, role, target, actor, "brandy", null);
        assertThat(keyX).isNotEqualTo(keyY);

        // Brand-X bans first → its own fresh row.
        ModActionRepository.RecordedBan x = repo.recordBan(keyX, actor, ModActionType.ACCESS_SUSPEND,
                "access", target, "abuse", "user", null, "pending", "brandx").block();
        assertThat(x.fresh()).isTrue();
        assertThat(x.action().domain()).isEqualTo("brandx");

        // Brand-Y bans the SAME actor+target+role, no idempotency token → MUST be a
        // distinct fresh row (NOT a dedup hit), scoped to brandy, never leaking brand-X.
        ModActionRepository.RecordedBan y = repo.recordBan(keyY, actor, ModActionType.ACCESS_SUSPEND,
                "access", target, "abuse", "user", null, "pending", "brandy").block();
        assertThat(y.fresh()).as("brand-Y must get its OWN fresh ban row, not dedup against brand-X")
                .isTrue();
        assertThat(y.action().domain()).as("brand-Y's read-back row is scoped to brandy, never brand-X")
                .isEqualTo("brandy");
        assertThat(y.action().id()).as("the two brands' rows are DISTINCT")
                .isNotEqualTo(x.action().id());

        // Two rows exist for this (actor, target) — one per brand, correctly partitioned.
        StepVerifier.create(db.sql("SELECT count(*) c FROM mod_action WHERE actor = :a AND target = :t")
                        .bind("a", actor).bind("t", target)
                        .map(r -> r.get("c", Long.class)).one())
                .assertNext(c -> assertThat(c).isEqualTo(2L))
                .verifyComplete();
        // Each scoped read sees only its own brand's row.
        StepVerifier.create(repo.listForDomain("brandx").collectList())
                .assertNext(rows -> assertThat(rows).hasSize(1)
                        .allSatisfy(a -> assertThat(a.domain()).isEqualTo("brandx")))
                .verifyComplete();
        StepVerifier.create(repo.listForDomain("brandy").collectList())
                .assertNext(rows -> assertThat(rows).hasSize(1)
                        .allSatisfy(a -> assertThat(a.domain()).isEqualTo("brandy")))
                .verifyComplete();
    }

    /**
     * CROSS-USER — the DB-level belt-and-suspenders: even if a key ever coincided across
     * brands (it cannot now), the COMPOSITE (dedup_key, domain) uniqueness still lets the
     * two brands keep DISTINCT rows. Two brands write the SAME literal dedup_key under
     * DIFFERENT domains → BOTH inserts are fresh; a same-brand redelivery of that key is
     * the only thing that dedups.
     */
    @Test
    void sameLiteralDedupKey_differentDomains_bothInsertFresh() {
        String sharedKey = "collide-1";
        ModActionRepository.RecordedBan x = repo.recordBan(sharedKey, "mod:x", ModActionType.ACCESS_SUSPEND,
                "access", "alice", "abuse", "user", null, "pending", "brandx").block();
        ModActionRepository.RecordedBan y = repo.recordBan(sharedKey, "mod:y", ModActionType.ACCESS_SUSPEND,
                "access", "alice", "abuse", "user", null, "pending", "brandy").block();
        assertThat(x.fresh()).isTrue();
        assertThat(y.fresh()).as("same key, OTHER domain → its OWN fresh row (composite uniqueness)")
                .isTrue();
        assertThat(x.action().domain()).isEqualTo("brandx");
        assertThat(y.action().domain()).isEqualTo("brandy");
        assertThat(y.action().id()).isNotEqualTo(x.action().id());

        // A same-brand redelivery of that key IS deduped (the within-brand idempotency
        // contract is preserved — back-compat).
        ModActionRepository.RecordedBan xRetry = repo.recordBan(sharedKey, "mod:x", ModActionType.ACCESS_SUSPEND,
                "access", "alice", "abuse", "user", null, "pending", "brandx").block();
        assertThat(xRetry.fresh()).as("same key + same brand → deduped").isFalse();
        assertThat(xRetry.action().id()).isEqualTo(x.action().id());
    }

    /** The domain-scoped read-back fails CLOSED on a null domain — never a global lookup
     *  that could surface another brand's row. */
    @Test
    void byDedupKey_nullDomain_failsClosed_empty() {
        repo.recordBan("k-1", "mod:x", ModActionType.ACCESS_SUSPEND, "access",
                "alice", "abuse", "user", null, "pending", "brandx").block();
        StepVerifier.create(repo.byDedupKey("k-1", null)).verifyComplete();   // empty: deny
        // The domain-scoped read returns the row for the RIGHT brand only.
        StepVerifier.create(repo.byDedupKey("k-1", "brandx"))
                .assertNext(a -> assertThat(a.domain()).isEqualTo("brandx"))
                .verifyComplete();
        StepVerifier.create(repo.byDedupKey("k-1", "brandy")).verifyComplete();   // wrong brand: empty
    }

    @Test
    void nullDomainScopedRead_failsClosed_empty() {
        banRow("x-1", "mod:x", "alice", "brandx").block();
        // A null domain (the fail-closed/injection signal from Roles.domainOf) yields an
        // EMPTY read — an unprovable/ambiguous tenant sees NOTHING, never another brand.
        StepVerifier.create(repo.listForDomain(null)).verifyComplete();
        StepVerifier.create(repo.listByActorForDomain("mod:x", null)).verifyComplete();
    }

    @Test
    void unscopedList_isTheSuperadminCrossDomainView_seesBothBrands() {
        banRow("x-1", "mod:x", "alice", "brandx").block();
        banRow("y-1", "mod:y", "carol", "brandy").block();
        // The UNSCOPED list() is the SUPERADMIN view — it sees every brand. (The
        // controller gates this behind Roles.isSuperadmin; here we assert the repo
        // contract.)
        StepVerifier.create(repo.list().collectList())
                .assertNext(rows -> assertThat(rows)
                        .extracting(ModAction::domain)
                        .containsExactlyInAnyOrder("brandx", "brandy"))
                .verifyComplete();
    }

    // ── CONCURRENT — interleaved cross-brand writes stay partitioned ──────────

    @Test
    void concurrentCrossBrandWrites_stayPartitioned() {
        int per = 25;
        AtomicInteger seq = new AtomicInteger();
        // Interleave brand-X and brand-Y ban writes concurrently (distinct dedup keys),
        // then assert each scoped read returns exactly its own brand's rows and nothing
        // from the other.
        var writes = reactor.core.publisher.Flux.range(0, per * 2)
                .parallel(8)
                .runOn(reactor.core.scheduler.Schedulers.parallel())
                .flatMap(i -> {
                    boolean x = (i % 2 == 0);
                    String brand = x ? "brandx" : "brandy";
                    int n = seq.incrementAndGet();
                    return banRow(brand + "-" + n, "mod:" + brand, "t" + n, brand);
                })
                .sequential();
        StepVerifier.create(writes).expectNextCount(per * 2L).verifyComplete();

        List<ModAction> xs = repo.listForDomain("brandx").collectList().block();
        List<ModAction> ys = repo.listForDomain("brandy").collectList().block();
        assertThat(xs).hasSize(per).allSatisfy(a -> assertThat(a.domain()).isEqualTo("brandx"));
        assertThat(ys).hasSize(per).allSatisfy(a -> assertThat(a.domain()).isEqualTo("brandy"));
        // No row appears in both partitions (ids are disjoint across brands).
        assertThat(xs).extracting(ModAction::id).doesNotContainAnyElementsOf(
                ys.stream().map(ModAction::id).toList());
    }
}
