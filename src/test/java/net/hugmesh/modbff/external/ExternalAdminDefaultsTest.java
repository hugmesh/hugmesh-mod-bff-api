package net.hugmesh.modbff.external;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.MutablePropertySources;
import org.springframework.core.env.StandardEnvironment;
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
 *
 * <p>TWO LAYERS, TWO RUNNERS. The default a container resolves is the product of two
 * files: the {@code @Value} fallbacks in {@link ExternalAdminConfig} (what applies when the
 * key is absent) and the packaged {@code application.yml} (which always defines the key as
 * {@code ${ENV:false}}). {@link #codeDefaults} loads no yml at all, so only the
 * {@code @Value} fallbacks decide; {@link #shippedYml} loads the packaged yml through
 * Spring Boot's real ConfigData machinery with NO profile — i.e. exactly what a pod with no
 * {@code MATRIX_ADMIN_*} env resolves — and asserts the RESOLVED property, not the source
 * text. A 2026-09-16 review measured that the text-only assertions further down are
 * bypassed by {@code enabled: true  # was ${MATRIX_ADMIN_ENABLED:false}} and by appending
 * an unconditioned second YAML document; the resolved-value tests catch both.
 */
class ExternalAdminDefaultsTest {

    /**
     * Strips the host's environment variables and {@code -D} system properties from the
     * runner so the host can neither mask a flipped default nor fake one. Spring's relaxed
     * binding maps {@code external.matrix.enabled} to {@code EXTERNAL_MATRIX_ENABLED}, so
     * without this an exported {@code EXTERNAL_MATRIX_ENABLED=false} keeps every test here
     * green after the {@code @Value} default is flipped to {@code true} (a false GREEN,
     * measured 2026-09-16), and {@code =true} fails the clean tree (a false RED). Registered
     * FIRST so a host {@code SPRING_PROFILES_ACTIVE=test} cannot pull
     * {@code application-test.yml} — which pins {@code enabled: false} — into the shipped
     * runner either.
     */
    private static final ApplicationContextInitializer<ConfigurableApplicationContext> HOST_BLIND = context -> {
        MutablePropertySources sources = context.getEnvironment().getPropertySources();
        sources.remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
        sources.remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
    };

    /**
     * Dead-port base URLs, belt and braces only: every assertion below is satisfied before
     * any socket would be opened, and a mutated default that DID try to call out fails fast
     * against a closed port instead of resolving the in-cluster service DNS.
     */
    private static final String[] DEAD_BASE_URLS = {
        "external.matrix.base-url=http://localhost:0",
        "external.mastodon.base-url=http://localhost:0",
    };

    /**
     * Boots the real {@link ExternalAdminConfig} with the flag and token keys UNSET (only
     * the dead-port base URLs are supplied), so {@code enabled} and {@code admin-token}
     * come solely from the {@code @Value} defaults in that class.
     */
    private final ApplicationContextRunner codeDefaults = new ApplicationContextRunner()
            .withInitializer(HOST_BLIND)
            .withConfiguration(AutoConfigurations.of(PropertyPlaceholderAutoConfiguration.class))
            .withBean(WebClient.Builder.class, WebClient::builder)
            .withUserConfiguration(ExternalAdminConfig.class)
            .withPropertyValues(DEAD_BASE_URLS);

    /**
     * Loads the PACKAGED {@code application.yml} through Spring Boot's ConfigData machinery
     * with no active profile, then boots {@link ExternalAdminConfig} on top of it: what a
     * container with no {@code MATRIX_ADMIN_*} / {@code MASTODON_ADMIN_*} env resolves. Only
     * the base URLs are overridden (dead port, see above); the keys under test are exactly
     * what the yml yields.
     */
    private final ApplicationContextRunner shippedYml = new ApplicationContextRunner()
            .withInitializer(HOST_BLIND)
            .withInitializer(new ConfigDataApplicationContextInitializer())
            .withConfiguration(AutoConfigurations.of(PropertyPlaceholderAutoConfiguration.class))
            .withBean(WebClient.Builder.class, WebClient::builder)
            .withUserConfiguration(ExternalAdminConfig.class)
            .withPropertyValues(DEAD_BASE_URLS);

    @Test
    void matrixAdminClient_defaultsToDisabled_soBlockUserIsStubbed() {
        codeDefaults.run(context -> {
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
        codeDefaults.run(context -> {
            MastodonAdminClient mastodon = context.getBean(MastodonAdminClient.class);
            StepVerifier.create(mastodon.blockUser("@spam@evil.example"))
                    .assertNext(o -> assertThat(o.isStubbed()).isTrue())
                    .verifyComplete();
        });
    }

    /**
     * The {@code @Value} default of each {@code admin-token} must be BLANK. Enabling a client
     * with the token key still unset must therefore degrade with {@code no-admin-token} and
     * make no call; an inlined token default would instead try to post (matrix) or PATCH
     * (mastodon) against the dead port and yield a different outcome.
     */
    @Test
    void codeDefaults_adminTokensBlank_soEnabledClientsDegradeInsteadOfCalling() {
        codeDefaults
                .withPropertyValues("external.matrix.enabled=true", "external.mastodon.enabled=true")
                .run(context -> {
                    StepVerifier.create(context.getBean(MatrixAdminClient.class).blockUser("@spam:evil.example"))
                            .assertNext(o -> assertThat(o.result()).isEqualTo("degraded:no-admin-token"))
                            .verifyComplete();
                    StepVerifier.create(context.getBean(MastodonAdminClient.class).blockUser("@spam@evil.example"))
                            .assertNext(o -> assertThat(o.result()).isEqualTo("degraded:no-admin-token"))
                            .verifyComplete();
                });
    }

    /** The contract for a real pod: the packaged yml, resolved, yields {@code false} for both flags. */
    @Test
    void shippedYml_resolvesBothAdminFlagsFalse_andClientsAreStubbed() {
        shippedYml.run(context -> {
            assertThat(context.getEnvironment().getProperty("external.matrix.enabled"))
                    .as("resolved external.matrix.enabled").isEqualTo("false");
            assertThat(context.getEnvironment().getProperty("external.mastodon.enabled"))
                    .as("resolved external.mastodon.enabled").isEqualTo("false");
            StepVerifier.create(context.getBean(MatrixAdminClient.class).blockUser("@spam:evil.example"))
                    .assertNext(o -> assertThat(o.isStubbed()).as("matrix outcome %s", o.result()).isTrue())
                    .verifyComplete();
            StepVerifier.create(context.getBean(MastodonAdminClient.class).blockUser("@spam@evil.example"))
                    .assertNext(o -> assertThat(o.isStubbed()).as("mastodon outcome %s", o.result()).isTrue())
                    .verifyComplete();
        });
    }

    /** The packaged yml must resolve both admin bearers to an EMPTY string when no env supplies them. */
    @Test
    void shippedYml_resolvesBothAdminTokensBlank() {
        shippedYml.run(context -> {
            assertThat(context.getEnvironment().getProperty("external.matrix.admin-token"))
                    .as("resolved external.matrix.admin-token").isNotNull().isEmpty();
            assertThat(context.getEnvironment().getProperty("external.mastodon.admin-token"))
                    .as("resolved external.mastodon.admin-token").isNotNull().isEmpty();
        });
    }

    /**
     * Fast first line, NOT the contract (the resolved-value tests above are): the packaged
     * {@code application.yml} still spells each flag as {@code ${ENV:false}}, which is the
     * form the deploy manifests are written against.
     */
    @Test
    void applicationYml_shipsBothHomeserverAdminFlagsDark() throws IOException {
        String yml = classpathResource("application.yml");
        assertThat(yml).contains("${MATRIX_ADMIN_ENABLED:false}");
        assertThat(yml).contains("${MASTODON_ADMIN_ENABLED:false}");
        assertThat(yml).doesNotContain("${MATRIX_ADMIN_ENABLED:true}");
        assertThat(yml).doesNotContain("${MASTODON_ADMIN_ENABLED:true}");
    }

    /** Fast first line: the admin bearers are still spelled as empty-default placeholders. */
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
