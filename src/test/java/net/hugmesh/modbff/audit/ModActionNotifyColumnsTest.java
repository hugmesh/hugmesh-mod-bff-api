package net.hugmesh.modbff.audit;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.r2dbc.test.autoconfigure.DataR2dbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import reactor.test.StepVerifier;
import net.hugmesh.commons.testsupport.PostgresTestSupport;
import net.hugmesh.modbff.support.PostgresSliceTestConfig;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * R2DBC slice test for the Notifications PR6 notify-directive columns
 * ({@code notify_channels} CSV + {@code notify_email_only}) over the REAL production
 * Liquibase schema (changelog 008) on a Testcontainers-Postgres store
 * ({@link PostgresSliceTestConfig}). Proves the directive round-trips on the same DDL
 * that runs in prod, and that the legacy directive-less ban leaves both columns null.
 * Moved off H2 because the shared changelog now also applies the DB-generated-id 009
 * ({@code pgcrypto}) which H2 cannot run.
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, ModActionRepository.class})
class ModActionNotifyColumnsTest extends PostgresTestSupport {

    @Autowired ModActionRepository repo;

    @Test
    void recordBan_withDirective_roundTripsTheNotifyColumns() {
        StepVerifier.create(repo.recordBan("dk-notify-1", "mod:bob", "access.suspend", "access",
                        "alice", "abuse", "user", null, "pending", "brandx",
                        "in-app,matrix", Boolean.FALSE))
                .assertNext(rb -> {
                    assertThat(rb.fresh()).isTrue();
                    assertThat(rb.action().notifyChannels()).isEqualTo("in-app,matrix");
                    assertThat(rb.action().notifyEmailOnly()).isFalse();
                    assertThat(rb.action().domain()).isEqualTo("brandx");
                })
                .verifyComplete();
    }

    @Test
    void recordBan_emailOnly_persistsTrue() {
        StepVerifier.create(repo.recordBan("dk-notify-2", "mod:carol", "access.suspend", "access",
                        "bob", null, "user", null, "pending", "brandx",
                        "in-app,email", Boolean.TRUE))
                .assertNext(rb -> {
                    assertThat(rb.action().notifyChannels()).isEqualTo("in-app,email");
                    assertThat(rb.action().notifyEmailOnly()).isTrue();
                })
                .verifyComplete();
    }

    @Test
    void recordBan_legacyNoDirective_leavesNotifyColumnsNull() {
        StepVerifier.create(repo.recordBan("dk-notify-3", "mod:dave", "access.suspend", "access",
                        "carol", null, "user", null, "pending", "brandx"))
                .assertNext(rb -> {
                    assertThat(rb.action().notifyChannels()).isNull();
                    assertThat(rb.action().notifyEmailOnly()).isNull();
                })
                .verifyComplete();
    }
}
