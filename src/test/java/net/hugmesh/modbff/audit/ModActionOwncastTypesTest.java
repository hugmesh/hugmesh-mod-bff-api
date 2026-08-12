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

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The new OWNCAST live-stream moderation types (changelog 010 + {@link ModActionType}).
 * The kill/hide/restore effect is owned by hugmesh-owncast-bff-api; these verbs make
 * those events first-class in THIS BFF's mod_action central ledger. Proven over the REAL
 * Liquibase schema (the widened {@code ck_mod_action_action} +
 * {@code ck_mod_action_platform} CHECKs) on a Testcontainers-Postgres store
 * ({@link PostgresSliceTestConfig}). Delineated per the test standard:
 *
 * <ul>
 *   <li>USER-SITUATIONAL — each owncast.* verb on the 'owncast' platform inserts cleanly
 *       and round-trips through the repository; a domain-scoped read isolates it.</li>
 *   <li>CROSS-USER / NEGATIVE — an unknown owncast verb or platform is still rejected by
 *       the closed vocabulary (the API&lt;-&gt;DB parity the constraint defends).</li>
 *   <li>PARITY (regression guard) — EVERY {@link ModActionType} constant inserts
 *       cleanly on its platform. This is the guard that was missing when
 *       {@code federation.finding-resolve} (PR #54) landed in the API vocabulary
 *       WITHOUT a CHECK widen — every resolveFinding audit INSERT would have violated
 *       {@code ck_mod_action_action} at runtime; changelog 010 restores parity and this
 *       test keeps the two vocabularies from drifting again.</li>
 * </ul>
 */
@DataR2dbcTest
@ActiveProfiles("test")
@Import({PostgresSliceTestConfig.class, ModActionRepository.class})
class ModActionOwncastTypesTest extends PostgresTestSupport {

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
    void allOwncastVerbs_onOwncastPlatform_insertCleanly() {
        for (String action : new String[]{
                ModActionType.OWNCAST_HIDE, ModActionType.OWNCAST_KILL,
                ModActionType.OWNCAST_RESTORE}) {
            StepVerifier.create(insert("owncast", action).fetch().rowsUpdated())
                    .assertNext(n -> assertThat(n).isEqualTo(1L))
                    .verifyComplete();
        }
    }

    @Test
    void owncastKill_recordsAndReadsBack_domainScoped() {
        StepVerifier.create(repo.record("mod:bob", ModActionType.OWNCAST_KILL, "owncast",
                        "streamer:dave", "abusive stream", "ok", "brandx"))
                .assertNext(a -> {
                    assertThat(a.action()).isEqualTo("owncast.kill");
                    assertThat(a.platform()).isEqualTo("owncast");
                    assertThat(a.target()).isEqualTo("streamer:dave");
                    assertThat(a.domain()).isEqualTo("brandx");
                })
                .verifyComplete();

        StepVerifier.create(repo.listForDomain("brandx"))
                .assertNext(a -> assertThat(a.action()).isEqualTo("owncast.kill"))
                .verifyComplete();
    }

    /** The honest degraded outcome (owncast-bff down → effect NOT landed) is persistable
     *  verbatim in the result column — the ledger never launders a failure into 'ok'. */
    @Test
    void owncastHide_degradedOutcome_roundTripsInResultColumn() {
        StepVerifier.create(repo.record("mod:bob", ModActionType.OWNCAST_HIDE, "owncast",
                        "streamer:carol", null, "degraded:WebClientRequestException", "brandx"))
                .assertNext(a -> assertThat(a.result()).isEqualTo("degraded:WebClientRequestException"))
                .verifyComplete();
    }

    // ── NEGATIVE — the closed vocabulary still bounds the audit ────────────────

    @Test
    void unknownOwncastVerb_isRejectedByCheckConstraint() {
        StepVerifier.create(insert("owncast", "owncast.nuke-transcoder").fetch().rowsUpdated())
                .expectError()
                .verify();
    }

    @Test
    void unknownPlatform_isStillRejected() {
        // The 'owncast' platform is added, but an unknown platform is still rejected —
        // the widen did not loosen the closed vocabulary.
        StepVerifier.create(insert("peertube", ModActionType.OWNCAST_HIDE).fetch().rowsUpdated())
                .expectError()
                .verify();
    }

    // ── PARITY — every ModActionType constant is insertable (API<->DB) ────────

    @Test
    void everyModActionTypeConstant_insertsCleanly_onItsPlatform() {
        List<String> verbs = allModActionTypeConstants();
        assertThat(verbs).as("sanity: the closed vocabulary is non-trivial").hasSizeGreaterThan(10);
        for (String verb : verbs) {
            StepVerifier.create(insert(platformFor(verb), verb).fetch().rowsUpdated())
                    .as("ModActionType '" + verb + "' must satisfy ck_mod_action_action "
                            + "(API<->DB CHECK parity)")
                    .assertNext(n -> assertThat(n).isEqualTo(1L))
                    .verifyComplete();
        }
    }

    /** Reflect the full closed vocabulary off {@link ModActionType} so a NEW verb added
     *  without a CHECK widen fails THIS test instead of the first runtime insert. */
    private static List<String> allModActionTypeConstants() {
        List<String> out = new ArrayList<>();
        for (Field f : ModActionType.class.getDeclaredFields()) {
            if (Modifier.isStatic(f.getModifiers()) && f.getType() == String.class) {
                try {
                    out.add((String) f.get(null));
                } catch (IllegalAccessException e) {
                    throw new IllegalStateException(e);
                }
            }
        }
        return out;
    }

    /** Verb-prefix → platform column value (the pairing each surface actually writes). */
    private static String platformFor(String verb) {
        String prefix = verb.substring(0, verb.indexOf('.'));
        return switch (prefix) {
            case "access"     -> "access";
            case "domain"     -> "domain-lock";
            default           -> prefix;   // matrix | mastodon | federation | wiki | owncast
        };
    }
}
