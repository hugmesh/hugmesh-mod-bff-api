package net.hugmesh.modbff.external;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the SHIPPED-DARK defaults of the external homeserver admin integrations.
 *
 * <p>WHY THIS EXISTS. {@code ExternalAdminClientTest} constructs the clients with an
 * explicit {@code enabled} boolean, and {@code application-test.yml} pins
 * {@code external.{matrix,mastodon}.enabled: false} for every {@code @SpringBootTest}.
 * Between them, NOTHING in the suite ever observed the shipped default — flipping
 * {@code ExternalAdminConfig}'s {@code @Value} default OR {@code application.yml}'s
 * {@code ${MATRIX_ADMIN_ENABLED:false}} to {@code true} left all 96 tests of the
 * block-path classes green (measured 2026-09-10, hugmesh-mod-bff-api#1). The operator's
 * decision on #1 is that the Matrix admin transport keeps the {@code deactivate} verb and
 * STAYS DARK, so the default itself is now a tested contract and not a convention.
 *
 * <p>WHAT WOULD BREAK IF THIS FLIPPED. {@code MATRIX_ADMIN_ENABLED=true} plus a mounted
 * {@code tuwunel-admin} token makes {@code /bff/mod/block} post
 * {@code !admin users deactivate <mxid>} into the live tuwunel admin room. On tuwunel that
 * is IRREVERSIBLE — there is no {@code !admin users activate} verb — so the flag must only
 * ever be turned on deliberately, per-environment, never by an edited default.
 */
class ExternalAdminDefaultsTest {

    /**
     * Boots the real {@link ExternalAdminConfig} with NO properties set, so every value
     * comes from the {@code @Value} defaults in that class. The base URLs are pointed at a
     * dead port purely as a belt-and-braces guard: both assertions below are satisfied
     * without any socket being opened.
     */
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PropertyPlaceholderAutoConfiguration.class))
            .withBean(WebClient.Builder.class, WebClient::builder)
            .withUserConfiguration(ExternalAdminConfig.class)
            .withPropertyValues(
                    "external.matrix.base-url=http://localhost:0",
                    "external.mastodon.base-url=http://localhost:0");

    @Test
    void matrixAdminClient_defaultsToDisabled_soBlockUserIsStubbed() {
        runner.run(context -> {
            MatrixAdminClient matrix = context.getBean(MatrixAdminClient.class);
            // stubbed (not merely degraded) is the proof that `enabled` defaulted false:
            // an enabled client with the default blank token would return
            // degraded:no-admin-token instead, and a tokened one would post the command.
            StepVerifier.create(matrix.blockUser("@spam:evil.example"))
                    .assertNext(o -> assertThat(o.isStubbed()).isTrue())
                    .verifyComplete();
        });
    }

    @Test
    void mastodonAdminClient_defaultsToDisabled_soBlockUserIsStubbed() {
        runner.run(context -> {
            MastodonAdminClient mastodon = context.getBean(MastodonAdminClient.class);
            StepVerifier.create(mastodon.blockUser("@spam@evil.example"))
                    .assertNext(o -> assertThat(o.isStubbed()).isTrue())
                    .verifyComplete();
        });
    }

    /**
     * The {@code @Value} defaults above are only half the contract: the packaged
     * {@code application.yml} re-declares each flag as {@code ${ENV:false}}, and THAT
     * literal is what a container actually resolves. Assert the shipped placeholder
     * defaults are false so an edit there is caught too.
     */
    @Test
    void applicationYml_shipsBothHomeserverAdminFlagsDark() throws IOException {
        String yml = classpathResource("application.yml");
        assertThat(yml).contains("${MATRIX_ADMIN_ENABLED:false}");
        assertThat(yml).contains("${MASTODON_ADMIN_ENABLED:false}");
        assertThat(yml).doesNotContain("${MATRIX_ADMIN_ENABLED:true}");
        assertThat(yml).doesNotContain("${MASTODON_ADMIN_ENABLED:true}");
    }

    /** The admin bearers must never be inlined as a literal default in the packaged config. */
    @Test
    void applicationYml_shipsNoInlinedAdminToken() throws IOException {
        String yml = classpathResource("application.yml");
        assertThat(yml).contains("${MATRIX_ADMIN_TOKEN:}");
        assertThat(yml).contains("${MASTODON_ADMIN_TOKEN:}");
    }

    private String classpathResource(String name) throws IOException {
        try (InputStream in = getClass().getClassLoader().getResourceAsStream(name)) {
            assertThat(in).as("classpath resource %s", name).isNotNull();
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
