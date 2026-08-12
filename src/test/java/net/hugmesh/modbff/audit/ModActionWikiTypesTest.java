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

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The new WIKI access-overlay moderation types (changelog 007 + {@link ModActionType}).
 * The grant/timeout/ban/restore overlay is owned by hugmesh-wiki-bff-api; these verbs
 * make those events first-class in THIS BFF's mod_action audit/queue surface. Proven over
 * the REAL Liquibase schema (the widened {@code ck_mod_action_action} +
 * {@code ck_mod_action_platform} CHECKs, plus the DB-generated-id 009) on a
 * Testcontainers-Postgres store ({@link PostgresSliceTestConfig}). Delineated per the test
 * standard:
 *
 * <ul>
 *   <li>USER-SITUATIONAL — each wiki.* verb on the 'wiki' platform inserts cleanly and
 *       round-trips through the repository; a domain-scoped read isolates it.</li>
 *   <li>CROSS-USER / NEGATIVE — a bad wiki action OR the 'wiki' platform paired with a
 *       non-wiki action vocabulary is still bounded by the closed vocabulary: an unknown
 *       {@code wiki.*} verb is rejected by the DB CHECK (the API&lt;-&gt;DB parity the
 *       constraint defends).</li>
 * </ul>
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, ModActionRepository.class})
class ModActionWikiTypesTest extends PostgresTestSupport {

    @Autowired ModActionRepository repo;
    @Autowired DatabaseClient db;

    /** Each method starts from an empty table so the per-domain read assertions are exact
     *  (this class's methods share one container db). */
    @BeforeEach
    void clean() {
        db.sql("DELETE FROM mod_action").fetch().rowsUpdated().block();
    }

    private DatabaseClient.GenericExecuteSpec insert(String platform, String action) {
        // No id supplied — the DB fills it from the gen_random_uuid() DEFAULT (009).
        return db.sql("INSERT INTO mod_action (actor, action, platform, target, result, ts, domain) "
                        + "VALUES ('mod:x', :action, :platform, 't', 'ok', now(), 'default')")
                .bind("action", action)
                .bind("platform", platform);
    }

    // ── USER-SITUATIONAL — the new verbs insert + round-trip ──────────────────

    @Test
    void allWikiVerbs_onWikiPlatform_insertCleanly() {
        for (String action : new String[]{
                ModActionType.WIKI_GRANT, ModActionType.WIKI_TIMEOUT,
                ModActionType.WIKI_BAN, ModActionType.WIKI_RESTORE}) {
            StepVerifier.create(insert("wiki", action).fetch().rowsUpdated())
                    .assertNext(n -> assertThat(n).isEqualTo(1L))
                    .verifyComplete();
        }
    }

    @Test
    void wikiGrant_recordsAndReadsBack_domainScoped() {
        StepVerifier.create(repo.record("mod:bob", ModActionType.WIKI_GRANT, "wiki",
                        "user:carol", "trusted contributor", "ok", "brandx"))
                .assertNext(a -> {
                    assertThat(a.action()).isEqualTo("wiki.grant");
                    assertThat(a.platform()).isEqualTo("wiki");
                    assertThat(a.target()).isEqualTo("user:carol");
                    assertThat(a.domain()).isEqualTo("brandx");
                })
                .verifyComplete();

        StepVerifier.create(repo.listForDomain("brandx"))
                .assertNext(a -> assertThat(a.action()).isEqualTo("wiki.grant"))
                .verifyComplete();
    }

    @Test
    void wikiBan_viaRecordBan_isIdempotentAndDomainScoped() {
        String key = ModActionKey.ban(ModActionType.WIKI_BAN, "WIKI", "dave", "mod:bob", "brandx", "idem-1");
        // First ban — fresh insert.
        StepVerifier.create(repo.recordBan(key, "mod:bob", ModActionType.WIKI_BAN, "wiki",
                        "user:dave", "abuse", "user", null, "pending", "brandx"))
                .assertNext(rb -> {
                    assertThat(rb.fresh()).isTrue();
                    assertThat(rb.action().action()).isEqualTo("wiki.ban");
                    assertThat(rb.action().platform()).isEqualTo("wiki");
                })
                .verifyComplete();
        // Redelivery of the same key — deduped (no second row), same persisted row.
        StepVerifier.create(repo.recordBan(key, "mod:bob", ModActionType.WIKI_BAN, "wiki",
                        "user:dave", "abuse", "user", null, "pending", "brandx"))
                .assertNext(rb -> assertThat(rb.fresh()).isFalse())
                .verifyComplete();
    }

    @Test
    void wikiTimeout_viaRecordBan_carriesFutureExpiry() {
        String key = ModActionKey.ban(ModActionType.WIKI_TIMEOUT, "WIKI", "erin", "mod:bob", "brandx", null);
        LocalDateTime exp = LocalDateTime.now().plusHours(1);
        StepVerifier.create(repo.recordBan(key, "mod:bob", ModActionType.WIKI_TIMEOUT, "wiki",
                        "user:erin", "cooldown", "user", exp, "pending", "brandx"))
                .assertNext(rb -> {
                    assertThat(rb.action().action()).isEqualTo("wiki.timeout");
                    assertThat(rb.action().expiresAt()).isNotNull();
                })
                .verifyComplete();
    }

    // ── NEGATIVE — the closed vocabulary still bounds the audit ────────────────

    @Test
    void unknownWikiVerb_isRejectedByCheckConstraint() {
        StepVerifier.create(insert("wiki", "wiki.nuke-everything").fetch().rowsUpdated())
                .expectError()
                .verify();
    }

    @Test
    void unknownPlatform_isStillRejected() {
        // The 'wiki' platform is added, but an unknown platform is still rejected — the
        // widen did not loosen the closed vocabulary.
        StepVerifier.create(insert("kiwix", ModActionType.WIKI_GRANT).fetch().rowsUpdated())
                .expectError()
                .verify();
    }
}
