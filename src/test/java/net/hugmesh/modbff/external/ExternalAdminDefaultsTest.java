package net.hugmesh.modbff.external;

import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Locale;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
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
 * block-path classes green (measured 2026-09-10, hugmesh-mod-bff-api#1). Both admin
 * integrations STAY DARK by operator decision, so the default itself is a tested contract
 * and not a convention.
 *
 * <p>WHAT WOULD BREAK IF THIS FLIPPED. For akkoma: {@code MASTODON_ADMIN_ENABLED=true} plus
 * a mounted token makes {@code /bff/mod/block} issue real pleroma-admin calls against the
 * live instance. For tuwunel the stake is smaller than it was: until decision 83b
 * (2026-09-23, hugmesh-mod-bff-api#23) {@code MatrixAdminClient} carried the one-way
 * {@code !admin users deactivate} transport, and a flipped {@code MATRIX_ADMIN_ENABLED}
 * would have armed it. That transport now lives only in hugmesh-admin-bff-api (behind its
 * own propose/confirm pair and its own {@code MATRIX_ADMIN_DEACTIVATE_*} flags), so the
 * Matrix flag here only changes an instance block's outcome from {@code stubbed} to
 * {@code requested:no-tuwunel-verb}. It stays dark anyway, and the probes below use
 * {@code blockInstance}, the one Matrix verb left.
 *
 * <p>THREE AXES, THREE RUNNERS. The default a deployment resolves is the product of the
 * {@code @Value} fallbacks in {@link ExternalAdminConfig} (what applies when the key is
 * absent), the packaged {@code application.yml} (which always defines the key as
 * {@code ${ENV:false}}), and any PROFILE-SCOPED configuration that is also packaged into
 * the jar. {@link #codeDefaults} loads no yml at all, so only the {@code @Value} fallbacks
 * decide; {@link #shippedYml} loads the packaged yml through Spring Boot's real ConfigData
 * machinery with NO profile — i.e. exactly what a cluster pod resolves, since
 * {@code specs/cluster/manifests/mod-bff-api/deployment.yaml} sets no
 * {@code SPRING_PROFILES_ACTIVE} — and asserts the RESOLVED property, not the source text;
 * {@link #shippedYmlUnder} repeats that resolution under each profile the jar can activate.
 *
 * <p>WHY THE THIRD AXIS EXISTS (2026-09-17, hugmesh-mod-bff-api#1 review). A 2026-09-16
 * review measured that the text-only assertions further down are bypassed by
 * {@code enabled: true  # was ${MATRIX_ADMIN_ENABLED:false}} and by appending an
 * unconditioned second YAML document; the resolved-value tests catch both. A 2026-09-17
 * review then found a bypass the resolved-value tests ALSO missed, along the one axis the
 * real deployment uses: a packaged {@code src/main/resources/application-casdoor.yml}
 * containing {@code external.matrix.enabled: true} left all 7 tests here green, and under
 * that profile the Matrix client stopped being stubbed (it then still carried
 * {@code blockUser}, removed under decision 83b). {@code casdoor} is the profile the
 * shipped container runs — hugmesh-generator {@code tests/stack/compose.local.yaml:882},
 * service {@code hugmesh-mod-bff-api}, sets {@code SPRING_PROFILES_ACTIVE: casdoor}. The
 * cause was that {@link #shippedYml} activates NO profile, so no profile-scoped document
 * is ever inside its envelope. This repo already
 * has the "a profile yml is packaged into the production jar" hazard open as #12, so the
 * axis is live, not hypothetical.
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

    /**
     * {@link #shippedYml}, but with {@code spring.profiles.active} set — so ConfigData also
     * pulls in every packaged {@code application-<profile>.yml} and every
     * {@code spring.config.activate.on-profile} document those profiles activate. The
     * property is supplied through {@code withPropertyValues}, which
     * {@code ApplicationContextRunner} applies BEFORE the initializers, so ConfigData sees it.
     */
    private ApplicationContextRunner shippedYmlUnder(String activeProfiles) {
        return shippedYml.withPropertyValues("spring.profiles.active=" + activeProfiles);
    }

    /**
     * Profiles this service is measured to be DEPLOYED under, independent of what happens to
     * be packaged today — so the profile axis is never vacuous, even on a tree where no
     * {@code application-<profile>.yml} exists at all. {@code casdoor}: hugmesh-generator
     * {@code tests/stack/compose.local.yaml:882} (service {@code hugmesh-mod-bff-api}). The
     * cluster manifest sets no {@code SPRING_PROFILES_ACTIVE}, which the profile-less
     * {@link #shippedYml} already covers. {@code dev}/{@code test} are the two names
     * {@code SecurityConfig}'s {@code @Profile} branches react to, so they are deployable
     * names too. Measured 2026-09-17.
     */
    private static final Set<String> DEPLOYED_PROFILES = Set.of("casdoor", "dev", "test");

    /**
     * Matches a {@code spring.config.activate.on-profile} key in EITHER spelling — the nested
     * {@code spring:/config:/activate:/on-profile:} form and the flattened
     * {@code spring.config.activate.on-profile:} form — because either one can hide a
     * flag-flipping document INSIDE a file whose name carries no profile.
     */
    private static final Pattern ON_PROFILE = Pattern.compile(
            "(?m)^\\s*(?:-\\s*)?(?:spring\\.config\\.activate\\.)?on-profile:\\s*(.+?)\\s*$");

    /** Packaged config file extensions ConfigData will load for a profile. */
    private static final Set<String> CONFIG_EXTENSIONS = Set.of(".yml", ".yaml", ".properties");

    /**
     * Every profile name this jar can activate configuration under: the measured
     * {@link #DEPLOYED_PROFILES}, plus one per packaged {@code application-<profile>.*} file,
     * plus every name any packaged file names in a {@code spring.config.activate.on-profile}
     * document. Derived at RUNTIME from the build output, so a file added tomorrow is covered
     * without anyone remembering to extend a list.
     */
    private static Set<String> packagedProfiles() throws Exception {
        URL anchor = ExternalAdminDefaultsTest.class.getClassLoader().getResource("application.yml");
        assertThat(anchor).as("packaged application.yml on the classpath").isNotNull();
        assertThat(anchor.getProtocol())
                .as("this scan enumerates the build output directory; run it from target/classes, "
                        + "not from a packaged jar")
                .isEqualTo("file");
        Path packagedRoot = Paths.get(anchor.toURI()).getParent();

        Set<String> profiles = new TreeSet<>(DEPLOYED_PROFILES);
        try (Stream<Path> entries = Files.list(packagedRoot)) {
            for (Path entry : entries.toList()) {
                String name = entry.getFileName().toString();
                boolean config = CONFIG_EXTENSIONS.stream().anyMatch(name::endsWith);
                if (!config || !Files.isRegularFile(entry)) {
                    continue;
                }
                if (name.startsWith("application-")) {
                    profiles.add(name.substring("application-".length(), name.lastIndexOf('.')));
                }
                if (name.startsWith("application")) {
                    profiles.addAll(onProfileNames(Files.readString(entry, StandardCharsets.UTF_8)));
                }
            }
        }
        return profiles;
    }

    /**
     * The bare profile names a config document activates on. Splits the expression form
     * ({@code a | b}, {@code a & b}, {@code a,b}) and drops the {@code !} of a negation — the
     * point is to collect every name worth ACTIVATING, not to evaluate the expression.
     */
    private static Set<String> onProfileNames(String configText) {
        Set<String> names = new TreeSet<>();
        Matcher m = ON_PROFILE.matcher(configText);
        while (m.find()) {
            String expression = m.group(1).replace("\"", "").replace("'", "");
            for (String token : expression.split("[,|&()\\[\\]\\s]+")) {
                String name = token.startsWith("!") ? token.substring(1) : token;
                if (!name.isBlank()) {
                    names.add(name.toLowerCase(Locale.ROOT));
                }
            }
        }
        return names;
    }

    /**
     * THE PROFILE AXIS. Resolve the packaged configuration once per activatable profile, and
     * once with all of them active together (a flip that only appears in combination is still
     * a flip), and assert the two homeserver-admin flags are still dark and both clients are
     * still stubbed. A packaged {@code application-casdoor.yml} setting
     * {@code external.matrix.enabled: true} — the bypass measured on 2026-09-17, invisible to
     * every other test in this class — fails here.
     */
    @Test
    void shippedYml_underEveryPackagedProfile_stillResolvesBothAdminFlagsDark() throws Exception {
        Set<String> profiles = packagedProfiles();
        assertThat(profiles)
                .as("the profile axis must not be vacuous — %s is the profile the shipped "
                        + "container runs under", "casdoor")
                .contains("casdoor");
        for (String profile : profiles) {
            assertShippedDarkUnder(profile);
        }
        assertShippedDarkUnder(String.join(",", profiles));
    }

    /** One resolution of the packaged configuration under {@code activeProfiles}. */
    private void assertShippedDarkUnder(String activeProfiles) {
        shippedYmlUnder(activeProfiles).run(context -> {
            assertThat(context.getEnvironment().getProperty("external.matrix.enabled"))
                    .as("resolved external.matrix.enabled under spring.profiles.active=%s",
                            activeProfiles)
                    .isEqualTo("false");
            assertThat(context.getEnvironment().getProperty("external.mastodon.enabled"))
                    .as("resolved external.mastodon.enabled under spring.profiles.active=%s",
                            activeProfiles)
                    .isEqualTo("false");
            StepVerifier.create(context.getBean(MatrixAdminClient.class).blockInstance("evil.example"))
                    .assertNext(o -> assertThat(o.isStubbed())
                            .as("matrix outcome %s under spring.profiles.active=%s",
                                    o.result(), activeProfiles)
                            .isTrue())
                    .verifyComplete();
            StepVerifier.create(context.getBean(MastodonAdminClient.class).blockUser("@spam@evil.example"))
                    .assertNext(o -> assertThat(o.isStubbed())
                            .as("mastodon outcome %s under spring.profiles.active=%s",
                                    o.result(), activeProfiles)
                            .isTrue())
                    .verifyComplete();
        });
    }

    /**
     * Non-vacuousness of the FILE half of {@link #packagedProfiles()}: every packaged
     * {@code application-<profile>.*} that exists must be represented in the discovered set,
     * so a scan that silently returned nothing (wrong directory, unreadable listing) fails
     * here rather than passing the profile axis by covering zero files. Deliberately does NOT
     * assert WHICH files exist — #12 is about removing {@code application-test.yml} from the
     * jar and this must not pin that bug in place.
     */
    @Test
    void packagedProfileDiscovery_seesEveryPackagedProfileDocument() throws Exception {
        URL anchor = ExternalAdminDefaultsTest.class.getClassLoader().getResource("application.yml");
        assertThat(anchor).isNotNull();
        Path packagedRoot = Paths.get(anchor.toURI()).getParent();
        Set<String> discovered = packagedProfiles();
        try (Stream<Path> entries = Files.list(packagedRoot)) {
            for (Path entry : entries.toList()) {
                String name = entry.getFileName().toString();
                if (!name.startsWith("application-")
                        || CONFIG_EXTENSIONS.stream().noneMatch(name::endsWith)) {
                    continue;
                }
                assertThat(discovered)
                        .as("profile derived from packaged %s", name)
                        .contains(name.substring("application-".length(), name.lastIndexOf('.')));
            }
        }
    }

    @Test
    void matrixAdminClient_defaultsToDisabled_soBlockInstanceIsStubbed() {
        codeDefaults.run(context -> {
            MatrixAdminClient matrix = context.getBean(MatrixAdminClient.class);
            // stubbed (not merely degraded) is the proof that `enabled` defaulted false:
            // an enabled client with the default blank token would return
            // degraded:no-admin-token instead, and a tokened one requested:no-tuwunel-verb.
            StepVerifier.create(matrix.blockInstance("evil.example"))
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
     * make no call; an inlined token default would instead record a request (matrix,
     * {@code requested:no-tuwunel-verb}) or PATCH (mastodon) against the dead port, and
     * yield a different outcome.
     */
    @Test
    void codeDefaults_adminTokensBlank_soEnabledClientsDegradeInsteadOfCalling() {
        codeDefaults
                .withPropertyValues("external.matrix.enabled=true", "external.mastodon.enabled=true")
                .run(context -> {
                    StepVerifier.create(context.getBean(MatrixAdminClient.class).blockInstance("evil.example"))
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
            StepVerifier.create(context.getBean(MatrixAdminClient.class).blockInstance("evil.example"))
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
