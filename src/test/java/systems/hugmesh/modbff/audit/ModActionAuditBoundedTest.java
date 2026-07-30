package systems.hugmesh.modbff.audit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.modbff.support.PostgresSliceTestConfig;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * UNBOUNDED-TABLE DoS GUARD for the {@code GET /bff/mod/audit} reads. The four audit
 * finder variants — {@link ModActionRepository#list(int)},
 * {@link ModActionRepository#listByActor(String, int)},
 * {@link ModActionRepository#listForDomain(String, int)} and
 * {@link ModActionRepository#listByActorForDomain(String, String, int)} — each push an
 * {@code ORDER BY ts DESC LIMIT :limit} into SQL, so a moderator's read can NEVER stream
 * the whole {@code mod_action} table into memory. This slice runs the REAL repository
 * against a Testcontainers-Postgres store with the REAL production Liquibase changelog
 * applied (the {@link PostgresSliceTestConfig} pattern), and asserts:
 *
 * <ul>
 *   <li><b>CAP</b> — with MORE rows than the hard ceiling
 *       ({@link ModActionRepository#MAX_AUDIT_LIMIT}) in the table, EVERY variant returns
 *       at most that ceiling even when asked for {@code Integer.MAX_VALUE}; the default
 *       (no caller limit) returns at most {@link ModActionRepository#DEFAULT_AUDIT_LIMIT};
 *       a small explicit limit is honoured exactly.</li>
 *   <li><b>NEWEST-FIRST</b> — the bounded read keeps the MOST RECENT rows
 *       ({@code ts DESC}), so the oldest rows are the ones dropped by the LIMIT.</li>
 *   <li><b>SCOPING PRESERVED</b> — the actor / domain predicates still apply under the
 *       LIMIT (a per-actor/per-domain bounded read returns only that actor's/domain's
 *       rows), and the clamp floor turns a non-positive caller limit into the default.</li>
 * </ul>
 *
 * <p>The timestamps are stamped DIRECTLY via {@link DatabaseClient} so the newest-first
 * ordering is deterministic (the facade's {@code record(...)} would stamp {@code now()}
 * for every row, which cannot prove which rows the LIMIT keeps).
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, ModActionRepository.class})
class ModActionAuditBoundedTest extends PostgresTestSupport {

    @Autowired ModActionRepository repo;
    @Autowired DatabaseClient db;

    /** Each method starts from an empty table (the class shares one container db). */
    @BeforeEach
    void clean() {
        db.sql("DELETE FROM mod_action").fetch().rowsUpdated().block();
    }

    /**
     * Insert {@code count} rows with strictly increasing {@code ts} (so row i is OLDER
     * than row i+1), stamped with the given actor + domain. Direct DB inserts (not the
     * facade) so we control the timestamps that drive newest-first ordering.
     */
    private void seed(int count, String actor, String domain) {
        LocalDateTime base = LocalDateTime.parse("2026-01-01T00:00:00");
        for (int i = 0; i < count; i++) {
            db.sql("INSERT INTO mod_action (actor, action, platform, target, reason, result, ts, domain) "
                            + "VALUES (:actor, 'matrix.block-user', 'matrix', :target, 'abuse', 'stubbed', :ts, :domain)")
                    .bind("actor", actor)
                    .bind("target", "@u" + i + ":evil.example")
                    .bind("ts", base.plusSeconds(i))     // strictly increasing => row i+1 is newer
                    .bind("domain", domain)
                    .fetch().rowsUpdated().block();
        }
    }

    // ── CAP: every variant is hard-bounded at MAX even when asked for MAX_VALUE ──────
    @Test
    void everyFinderVariant_isHardCappedAtMax_evenWhenAskedForMore() {
        int over = ModActionRepository.MAX_AUDIT_LIMIT + 25;     // more rows than the ceiling
        seed(over, "mod:bob", "brandx");

        // list(): UNSCOPED (superadmin) — capped at MAX even with Integer.MAX_VALUE asked.
        assertThat(repo.list(Integer.MAX_VALUE).count().block())
                .as("unscoped list() must be capped at MAX_AUDIT_LIMIT")
                .isEqualTo((long) ModActionRepository.MAX_AUDIT_LIMIT);

        // listByActor(): UNSCOPED per-actor — capped.
        assertThat(repo.listByActor("mod:bob", Integer.MAX_VALUE).count().block())
                .as("listByActor() must be capped at MAX_AUDIT_LIMIT")
                .isEqualTo((long) ModActionRepository.MAX_AUDIT_LIMIT);

        // listForDomain(): DOMAIN-SCOPED — capped.
        assertThat(repo.listForDomain("brandx", Integer.MAX_VALUE).count().block())
                .as("listForDomain() must be capped at MAX_AUDIT_LIMIT")
                .isEqualTo((long) ModActionRepository.MAX_AUDIT_LIMIT);

        // listByActorForDomain(): DOMAIN-SCOPED per-actor — capped.
        assertThat(repo.listByActorForDomain("mod:bob", "brandx", Integer.MAX_VALUE).count().block())
                .as("listByActorForDomain() must be capped at MAX_AUDIT_LIMIT")
                .isEqualTo((long) ModActionRepository.MAX_AUDIT_LIMIT);
    }

    // ── CAP: the no-limit (default) read is bounded to DEFAULT, not the whole table ──
    @Test
    void defaultRead_isBoundedToDefaultLimit_notTheWholeTable() {
        int over = ModActionRepository.DEFAULT_AUDIT_LIMIT + 50;
        seed(over, "mod:bob", "brandx");

        assertThat(repo.list().count().block())
                .as("the no-arg (default) list() must be bounded to DEFAULT_AUDIT_LIMIT")
                .isEqualTo((long) ModActionRepository.DEFAULT_AUDIT_LIMIT);
        assertThat(repo.listForDomain("brandx").count().block())
                .as("the no-arg (default) listForDomain() must be bounded to DEFAULT_AUDIT_LIMIT")
                .isEqualTo((long) ModActionRepository.DEFAULT_AUDIT_LIMIT);
        assertThat(repo.listByActor("mod:bob").count().block())
                .isEqualTo((long) ModActionRepository.DEFAULT_AUDIT_LIMIT);
        assertThat(repo.listByActorForDomain("mod:bob", "brandx").count().block())
                .isEqualTo((long) ModActionRepository.DEFAULT_AUDIT_LIMIT);
    }

    // ── CAP: a small explicit limit is honoured exactly, on every variant ───────────
    @Test
    void smallExplicitLimit_isHonouredExactly_onEveryVariant() {
        seed(20, "mod:bob", "brandx");

        assertThat(repo.list(5).count().block()).isEqualTo(5L);
        assertThat(repo.listByActor("mod:bob", 7).count().block()).isEqualTo(7L);
        assertThat(repo.listForDomain("brandx", 3).count().block()).isEqualTo(3L);
        assertThat(repo.listByActorForDomain("mod:bob", "brandx", 4).count().block()).isEqualTo(4L);
    }

    // ── NEWEST-FIRST: the LIMIT keeps the MOST RECENT rows, drops the oldest ─────────
    @Test
    void boundedRead_keepsNewestRows_inDescendingTsOrder() {
        // 10 rows; ts increases with the target index, so @u9 is the NEWEST, @u0 the OLDEST.
        seed(10, "mod:bob", "brandx");

        // Asking for the top 3 must return @u9, @u8, @u7 (newest first), NOT the oldest 3.
        List<ModAction> top3 = repo.list(3).collectList().block();
        assertThat(top3).extracting(ModAction::target)
                .containsExactly("@u9:evil.example", "@u8:evil.example", "@u7:evil.example");

        // ts must be strictly descending (newest-first contract preserved by ORDER BY ts DESC).
        assertThat(top3.get(0).ts()).isAfter(top3.get(1).ts());
        assertThat(top3.get(1).ts()).isAfter(top3.get(2).ts());

        // The same newest-first contract on the domain-scoped variant.
        StepVerifier.create(repo.listForDomain("brandx", 1))
                .assertNext(a -> assertThat(a.target()).isEqualTo("@u9:evil.example"))
                .verifyComplete();
    }

    // ── SCOPING PRESERVED under the LIMIT (actor + domain predicates still apply) ────
    @Test
    void scopingPredicates_stillApplyUnderTheLimit() {
        seed(5, "mod:alice", "brandx");
        seed(5, "mod:bob", "brandx");
        seed(5, "mod:bob", "brandy");

        // listForDomain bounds AND scopes: brandx has 10 rows (alice+bob); a big limit
        // returns exactly those 10, never brandy's.
        assertThat(repo.listForDomain("brandx", 1000).count().block())
                .as("listForDomain returns ONLY the requested brand's rows under the limit")
                .isEqualTo(10L);
        repo.listForDomain("brandx", 1000).collectList().block()
                .forEach(a -> assertThat(a.domain()).isEqualTo("brandx"));

        // listByActorForDomain bounds AND scopes to actor+domain: bob/brandx = 5 rows.
        assertThat(repo.listByActorForDomain("mod:bob", "brandx", 1000).count().block())
                .isEqualTo(5L);

        // listByActor (unscoped per-actor): bob has 10 rows across brandx+brandy.
        assertThat(repo.listByActor("mod:bob", 1000).count().block())
                .isEqualTo(10L);
    }

    // ── CLAMP FLOOR: a non-positive caller limit collapses to the default cap ────────
    @Test
    void nonPositiveLimit_clampsToDefault_neverUnbounded() {
        int over = ModActionRepository.DEFAULT_AUDIT_LIMIT + 10;
        seed(over, "mod:bob", "brandx");

        // 0 and negative are not "no limit" — they clamp UP to the default, never the table.
        assertThat(repo.list(0).count().block())
                .as("limit=0 must clamp to DEFAULT, not return the whole table")
                .isEqualTo((long) ModActionRepository.DEFAULT_AUDIT_LIMIT);
        assertThat(repo.listForDomain("brandx", -1).count().block())
                .as("a negative limit must clamp to DEFAULT")
                .isEqualTo((long) ModActionRepository.DEFAULT_AUDIT_LIMIT);

        // The pure clamp function contract (defense-in-depth ceiling + floor).
        assertThat(ModActionRepository.clampLimit(Integer.MAX_VALUE))
                .isEqualTo(ModActionRepository.MAX_AUDIT_LIMIT);
        assertThat(ModActionRepository.clampLimit(0))
                .isEqualTo(ModActionRepository.DEFAULT_AUDIT_LIMIT);
        assertThat(ModActionRepository.clampLimit(50)).isEqualTo(50);
    }
}
