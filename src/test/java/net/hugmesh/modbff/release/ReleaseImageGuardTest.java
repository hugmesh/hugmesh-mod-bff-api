package net.hugmesh.modbff.release;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pins the TWO Maven-registry contracts of this service's image build, so that adding the
 * GitHub one can never silently remove the GitLab one.
 *
 * <ul>
 *   <li><b>GitLab / local lane (historical, must not change).</b> The repo-root
 *       {@code settings.xml} points at {@code ${env.CI_API_V4_URL}/groups/${env.GITLAB_GROUP_ID}}
 *       with a {@code Job-Token} header, and the Dockerfile mounts the BuildKit secret
 *       {@code ci_job_token} and runs {@code ./mvnw -B -s settings.xml package}. The GitLab
 *       pipeline and hugmesh-generator's local compose / kind lane depend on exactly that:
 *       {@code scripts/patch-stack-src.sh} greps {@code settings.xml} for
 *       {@code CI_API_V4_URL}, and {@code scripts/kind-load-images.sh} refuses a Dockerfile
 *       that does not thread {@code -s settings.xml}. Both fail by wedging a long image
 *       build, not by saying so.</li>
 *   <li><b>GitHub release workflow (additive).</b> When the BuildKit secret
 *       {@code packages_read_token} is mounted the Dockerfile uses
 *       {@code .github/maven-ci-settings.xml} against GitHub Packages. That file must stay
 *       mirrors-free, carry no committed credential, and declare every upstream of the chain
 *       as both a repository and a plugin repository (the analyser rulesets are resolved
 *       from plugin repositories).</li>
 *   <li><b>No xtrace in the build step.</b> With a real token present, {@code sh -x} prints
 *       {@code export UPSTREAM_PACKAGES_TOKEN=<value>} into the BuildKit log, and
 *       build-push-action v6 uploads a build-record artifact holding raw BuildKit logs,
 *       which runner-side masking does not cover.</li>
 * </ul>
 *
 * <p>Reads the repository files directly (surefire runs with the project basedir as the
 * working directory). Comments are stripped before an ABSENCE is asserted, so a sentence
 * explaining why something is gone cannot satisfy or defeat a check.
 */
class ReleaseImageGuardTest {

    private static final Path ROOT = Path.of("").toAbsolutePath();
    private static final List<String> UPSTREAMS = List.of(
            "hugmesh-build-config", "hugmesh-parent", "hugmesh-commons", "hugmesh-auth-core");

    @Test
    @DisplayName("Dockerfile keeps the GitLab contract: ci_job_token mount, the ARG pair, literal -s settings.xml")
    void dockerfileKeepsGitLabContract() throws IOException {
        String dockerfile = code(read("Dockerfile"), "#");
        assertThat(dockerfile)
                .contains("--mount=type=secret,id=ci_job_token")
                .contains("ARG CI_API_V4_URL")
                .contains("ARG GITLAB_GROUP_ID");
        // The literal spelling: kind-load-images.sh greps for -s[[:space:]]+settings\.xml.
        assertThat(Pattern.compile("-s\\s+settings\\.xml\\s+package").matcher(dockerfile).find())
                .as("Dockerfile must still run `-s settings.xml package` verbatim in the no-secret branch")
                .isTrue();
    }

    @Test
    @DisplayName("Dockerfile adds the GitHub contract and does not xtrace the token")
    void dockerfileAddsGitHubContractWithoutXtrace() throws IOException {
        String dockerfile = code(read("Dockerfile"), "#");
        assertThat(dockerfile)
                .contains("--mount=type=secret,id=packages_read_token")
                .contains("ARG UPSTREAM_PACKAGES_ACTOR")
                .contains("-s .github/maven-ci-settings.xml");
        // `sh -euxc` (any flag cluster carrying x) or an explicit `set -x` would echo the token.
        assertThat(Pattern.compile("\\bsh\\s+-[a-z]*x[a-z]*\\b|\\bset\\s+-[a-z]*x").matcher(dockerfile).find())
                .as("the build RUN must not enable xtrace")
                .isFalse();
    }

    @Test
    @DisplayName("Repo-root settings.xml is still the GitLab registry and never names GitHub Packages")
    void rootSettingsStaysGitLab() throws IOException {
        String settings = read("settings.xml");
        assertThat(settings).contains("CI_API_V4_URL").contains("GITLAB_GROUP_ID").contains("Job-Token");
        assertThat(settings).doesNotContain("maven.pkg.github.com");
    }

    @Test
    @DisplayName(".github/maven-ci-settings.xml: no mirror, no committed secret, all upstreams as repo + plugin repo")
    void ciSettingsShape() throws Exception {
        Document doc = parse(read(".github/maven-ci-settings.xml"));
        assertThat(doc.getElementsByTagName("mirror").getLength()).as("mirrors-free").isZero();

        List<String> serverIds = new ArrayList<>();
        NodeList servers = doc.getElementsByTagName("server");
        for (int i = 0; i < servers.getLength(); i++) {
            Element server = (Element) servers.item(i);
            serverIds.add(text(server, "id"));
            assertThat(text(server, "password")).as("password of %s", text(server, "id"))
                    .isEqualTo("${env.UPSTREAM_PACKAGES_TOKEN}");
            assertThat(text(server, "username")).isEqualTo("${env.UPSTREAM_PACKAGES_ACTOR}");
        }
        List<String> expectedIds = UPSTREAMS.stream().map(u -> "github-" + u).toList();
        assertThat(serverIds).as("a consumer has read servers only; no `github` deploy server")
                .containsExactlyInAnyOrderElementsOf(expectedIds);

        for (String tag : Set.of("repository", "pluginRepository")) {
            NodeList repos = doc.getElementsByTagName(tag);
            List<String> found = new ArrayList<>();
            for (int i = 0; i < repos.getLength(); i++) {
                Element repo = (Element) repos.item(i);
                String id = text(repo, "id");
                found.add(id);
                assertThat(text(repo, "url")).isEqualTo(
                        "https://maven.pkg.github.com/hugmesh/" + id.substring("github-".length()));
            }
            assertThat(found).as("<%s> ids", tag).containsExactlyInAnyOrderElementsOf(expectedIds);
        }
    }

    @Test
    @DisplayName("release.yml (when present) feeds the GitHub contract and not the dead GitLab inputs")
    void releaseWorkflowUsesGitHubContract() throws IOException {
        Path wf = ROOT.resolve(".github/workflows/release.yml");
        org.junit.jupiter.api.Assumptions.assumeTrue(Files.exists(wf),
                "this repo has no release workflow yet; the Dockerfile/settings guards above still apply");
        String yaml = code(Files.readString(wf, StandardCharsets.UTF_8), "#");
        assertThat(yaml)
                .contains("packages_read_token=${{ secrets.PACKAGES_READ_TOKEN || secrets.GITHUB_TOKEN }}")
                .contains("UPSTREAM_PACKAGES_ACTOR=${{ secrets.PACKAGES_READ_ACTOR || github.actor }}")
                .contains("DOCKER_BUILD_RECORD_UPLOAD: false")
                .contains("Preflight - cross-repo package read");
        assertThat(yaml).as("the GitLab inputs these names replaced must not come back")
                .doesNotContain("ci_job_token=")
                .doesNotContain("CI_API_V4_URL=")
                .doesNotContain("GITLAB_GROUP_ID=");
        assertThat(yaml.indexOf("Preflight - cross-repo package read"))
                .as("the preflight must precede the image build")
                .isLessThan(yaml.indexOf("docker/build-push-action"));
    }

    private static String read(String relative) throws IOException {
        Path p = ROOT.resolve(relative);
        assertThat(p).as("%s must exist", relative).exists();
        return Files.readString(p, StandardCharsets.UTF_8);
    }

    /** Drops whole-line comments so prose cannot satisfy or defeat a check. */
    private static String code(String text, String commentPrefix) {
        StringBuilder out = new StringBuilder();
        for (String line : text.split("\n", -1)) {
            if (!line.stripLeading().startsWith(commentPrefix)) {
                out.append(line).append('\n');
            }
        }
        return out.toString();
    }

    private static Document parse(String xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        return f.newDocumentBuilder().parse(new java.io.ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)));
    }

    private static String text(Element parent, String child) {
        NodeList nodes = parent.getElementsByTagName(child);
        assertThat(nodes.getLength()).as("<%s> in <%s>", child, parent.getTagName()).isGreaterThan(0);
        return nodes.item(0).getTextContent().trim();
    }
}
