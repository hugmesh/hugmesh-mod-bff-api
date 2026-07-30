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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Idempotency / dedup slice test for the phase-2 ban surface over the
 * Testcontainers-Postgres store the REAL Liquibase changelog (incl. 003 + the
 * DB-generated-id 009) is applied to ({@link PostgresSliceTestConfig}). Proves the
 * at-least-once-safe contract: {@link ModActionRepository#recordBan} with the SAME
 * deterministic dedup key inserts exactly ONE row — the first call is {@code fresh=true},
 * a redelivery is {@code fresh=false} and returns the SAME persisted (DB-generated) id (so
 * the caller does NOT re-trigger the desired-state effect), while a DIFFERENT key inserts a
 * second row. Identical assertions to the former H2 slice; moved to Postgres because
 * {@code INSERT ... ON CONFLICT DO NOTHING RETURNING id} (the new fresh-signal) needs a real
 * Postgres.
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, ModActionRepository.class})
class ModActionDedupTest extends PostgresTestSupport {

    @Autowired ModActionRepository repo;
    @Autowired DatabaseClient db;

    private static final LocalDateTime TTL = LocalDateTime.parse("2030-01-01T00:00:00");

    /** Each method starts from an empty table so the per-key COUNT assertions are exact
     *  (this class's methods share one container db). */
    @BeforeEach
    void clean() {
        db.sql("DELETE FROM mod_action").fetch().rowsUpdated().block();
    }

    @Test
    void recordBan_sameDedupKey_insertsOnceAndDedupsRetry() {
        String key = ModActionKey.ban(ModActionType.ACCESS_SUSPEND, "ROLE_MATRIX", "alice", "mod:bob", "default", "idem-1");

        // First call inserts a fresh row.
        StepVerifier.create(repo.recordBan(key, "mod:bob", ModActionType.ACCESS_SUSPEND, "access",
                        "alice", "abuse", "user", TTL, "pending"))
                .assertNext(r -> {
                    assertThat(r.fresh()).isTrue();
                    assertThat(r.action().action()).isEqualTo("access.suspend");
                    assertThat(r.action().dedupKey()).isEqualTo(key);
                    assertThat(r.action().propagationState()).isEqualTo("pending");
                    assertThat(r.action().expiresAt()).isEqualTo(TTL);
                })
                .verifyComplete();

        // Redelivery with the SAME key: deduped (fresh=false), SAME persisted id.
        String firstId = repo.byDedupKey(key).block().id();
        StepVerifier.create(repo.recordBan(key, "mod:bob", ModActionType.ACCESS_SUSPEND, "access",
                        "alice", "abuse", "user", TTL, "pending"))
                .assertNext(r -> {
                    assertThat(r.fresh()).isFalse();
                    assertThat(r.action().id()).isEqualTo(firstId);
                })
                .verifyComplete();

        // Exactly ONE row exists for that key.
        StepVerifier.create(db.sql("SELECT count(*) c FROM mod_action WHERE dedup_key = :k")
                        .bind("k", key).map(row -> row.get("c", Long.class)).one())
                .assertNext(c -> assertThat(c).isEqualTo(1L))
                .verifyComplete();
    }

    @Test
    void recordBan_differentDedupKey_insertsSecondRow() {
        String k1 = ModActionKey.ban(ModActionType.ACCESS_SUSPEND, "ROLE_MASTODON", "carol", "mod:bob", "default", "a");
        String k2 = ModActionKey.ban(ModActionType.ACCESS_SUSPEND, "ROLE_MASTODON", "carol", "mod:bob", "default", "b");

        repo.recordBan(k1, "mod:bob", ModActionType.ACCESS_SUSPEND, "access", "carol",
                null, "user", null, "pending").block();
        StepVerifier.create(repo.recordBan(k2, "mod:bob", ModActionType.ACCESS_SUSPEND, "access", "carol",
                        null, "user", null, "pending"))
                .assertNext(r -> assertThat(r.fresh()).isTrue())
                .verifyComplete();

        StepVerifier.create(db.sql("SELECT count(*) c FROM mod_action WHERE target = :t")
                        .bind("t", "carol").map(row -> row.get("c", Long.class)).one())
                .assertNext(c -> assertThat(c).isEqualTo(2L))
                .verifyComplete();
    }

    @Test
    void recordBan_permanentBan_hasNullExpiry() {
        String key = ModActionKey.ban(ModActionType.ACCESS_SUSPEND, "PROFILE", "dave", "mod:bob", "default", null);
        StepVerifier.create(repo.recordBan(key, "mod:bob", ModActionType.ACCESS_SUSPEND, "access",
                        "dave", null, "profile", null, "pending"))
                .assertNext(r -> {
                    assertThat(r.fresh()).isTrue();
                    assertThat(r.action().expiresAt()).isNull();
                    assertThat(r.action().banType()).isEqualTo("profile");
                })
                .verifyComplete();
    }
}
