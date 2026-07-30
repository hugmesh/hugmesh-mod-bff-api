package systems.hugmesh.modbff.audit;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import systems.hugmesh.commons.testsupport.PostgresTestSupport;
import systems.hugmesh.modbff.support.PostgresSliceTestConfig;

/**
 * Proves the API↔DB parity CHECK constraints from changeset 002 actually reject a
 * bad insert at the database, over the SAME Testcontainers-Postgres store the real
 * Liquibase changelog is applied to ({@link PostgresSliceTestConfig}). A direct INSERT
 * that bypasses the controller (the threat the DB-level CHECK defends against) must fail
 * when {@code platform} or {@code action} is outside the closed vocabulary; a valid row
 * still inserts. The id is now OMITTED — the {@code gen_random_uuid()} DEFAULT (changelog
 * 009) fills it — so these inserts also exercise the DB-generated-id path.
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, ModActionRepository.class})
class ModActionConstraintsTest extends PostgresTestSupport {

    @Autowired DatabaseClient db;

    private DatabaseClient.GenericExecuteSpec insert(String platform, String action) {
        // No id supplied — the DB fills it from the gen_random_uuid() DEFAULT (009).
        return db.sql("INSERT INTO mod_action (actor, action, platform, target, result, ts) "
                        + "VALUES ('mod:x', :action, :platform, 't', 'ok', now())")
                .bind("action", action)
                .bind("platform", platform);
    }

    @Test
    void badPlatform_isRejectedByCheckConstraint() {
        StepVerifier.create(insert("irc", "matrix.block-user").fetch().rowsUpdated())
                .expectError()
                .verify();
    }

    @Test
    void badAction_isRejectedByCheckConstraint() {
        StepVerifier.create(insert("matrix", "matrix.nuke-everything").fetch().rowsUpdated())
                .expectError()
                .verify();
    }

    @Test
    void validRow_insertsCleanly() {
        StepVerifier.create(insert("federation", "federation.refer").fetch().rowsUpdated())
                .assertNext(n -> org.assertj.core.api.Assertions.assertThat(n).isEqualTo(1L))
                .verifyComplete();
    }
}
