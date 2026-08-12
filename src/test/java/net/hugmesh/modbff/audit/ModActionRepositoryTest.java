package net.hugmesh.modbff.audit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.modbff.support.PostgresSliceTestConfig;

/**
 * R2DBC slice test for the audit-table repository over a Testcontainers-Postgres store
 * that Liquibase applies the REAL production changelog over (the
 * {@link PostgresSliceTestConfig} pattern). Proves the {@code mod_action} DDL + the
 * repository's {@code INSERT ... RETURNING}/SELECT round-trip on the same schema that
 * runs in prod — including the reserved-word {@code target} column AND the
 * DB-generated-UUID-PK ({@code gen_random_uuid()} DEFAULT, changelog 009).
 *
 * <p>Moved off the H2 PostgreSQL-compat store ({@code TestDatabaseConfig}) because the
 * DB-generated-id exemplar needs {@code pgcrypto}/{@code gen_random_uuid()} and a reliable
 * {@code INSERT ... RETURNING}, NEITHER of which H2 provides. {@code PostgresTestSupport}
 * gives each test class a fresh container db, so the per-context isolation hack the H2
 * slices used ({@code @TestPropertySource}) is no longer needed.
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, ModActionRepository.class})
class ModActionRepositoryTest extends PostgresTestSupport {

    @Autowired ModActionRepository repo;
    @Autowired DatabaseClient db;

    /** Start each method from an empty table so the {@code list()} round-trip below
     *  asserts exactly the one row it wrote (the class's methods share one container db). */
    @BeforeEach
    void clean() {
        db.sql("DELETE FROM mod_action").fetch().rowsUpdated().block();
    }

    @Test
    void record_thenList_roundTripsOverRealLiquibaseSchema() {
        StepVerifier.create(
                        repo.record("mod:bob", ModActionType.MATRIX_BLOCK_USER, "matrix",
                                "@spam:evil.example", "abuse", "stubbed"))
                .assertNext(a -> {
                    // record() returns a populated DB-generated id (NOT app-minted).
                    org.assertj.core.api.Assertions.assertThat(a.id()).isNotBlank();
                    org.assertj.core.api.Assertions.assertThat(a.action()).isEqualTo("matrix.block-user");
                    org.assertj.core.api.Assertions.assertThat(a.target()).isEqualTo("@spam:evil.example");
                    org.assertj.core.api.Assertions.assertThat(a.result()).isEqualTo("stubbed");
                    org.assertj.core.api.Assertions.assertThat(a.ts()).isNotNull();
                })
                .verifyComplete();

        StepVerifier.create(repo.list())
                .assertNext(a -> org.assertj.core.api.Assertions.assertThat(a.actor()).isEqualTo("mod:bob"))
                .verifyComplete();
    }

    @Test
    void record_withNullReason_isAccepted() {
        StepVerifier.create(
                        repo.record("mod:carol", ModActionType.FEDERATION_REFER, "federation",
                                "moderation-request:7", null, "ok"))
                .assertNext(a -> org.assertj.core.api.Assertions.assertThat(a.reason()).isNull())
                .verifyComplete();
    }

    @Test
    void listByActor_filtersToOneModerator() {
        repo.record("mod:dave", ModActionType.MASTODON_BLOCK_INSTANCE, "mastodon",
                "evil.example", "spam", "stubbed").block();
        repo.record("mod:erin", ModActionType.MASTODON_BLOCK_USER, "mastodon",
                "@x:evil.example", "spam", "stubbed").block();

        StepVerifier.create(repo.listByActor("mod:dave"))
                .assertNext(a -> {
                    org.assertj.core.api.Assertions.assertThat(a.actor()).isEqualTo("mod:dave");
                    org.assertj.core.api.Assertions.assertThat(a.platform()).isEqualTo("mastodon");
                })
                .verifyComplete();
    }
}
