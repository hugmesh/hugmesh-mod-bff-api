package net.hugmesh.modbff;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DETERMINISTIC OpenAPI SPEC DUMP — the CI-friendly replacement for a manually-run
 * {@code gen:fetch} curl. This boots the full application context under the
 * {@code test} profile (where {@code /v3/api-docs} is PUBLIC — see
 * {@link net.hugmesh.modbff.config.SecurityConfig#devFilterChain}), GETs the
 * springdoc-generated OpenAPI 3 document, normalizes it to a STABLE byte form
 * (alphabetically-sorted keys + 2-space pretty print + trailing newline), and writes
 * it to a committed path.
 *
 * <p><b>Why a test, not a server:</b> the spec is produced as an ordinary build
 * artefact during {@code ./mvnw test} — no port to bind manually, no token, no
 * running BFF, no curl. The platform ng-openapi-gen typed client in the paired
 * hugmesh-mod-ui consumes the COMMITTED copy of this file; the docs pipeline reads
 * the same artefact.
 *
 * <p><b>Determinism:</b> springdoc emits keys in a non-deterministic order across
 * runs/JVMs, which would produce noisy diffs. {@link SerializationFeature#ORDER_MAP_ENTRIES_BY_KEYS}
 * re-serializes every object with sorted keys, so re-running the dump on an UNCHANGED
 * API yields a byte-identical file (idempotent). A change to any endpoint/DTO is the
 * ONLY thing that moves the file — which is exactly the review signal we want.
 *
 * <p><b>Drift guard (optional):</b> the {@code -Dopenapi.spec.check=true} flag flips
 * this from "write" to "assert the committed file already matches" — wire that into a
 * CI verify lane to fail a build whose committed spec is stale. Default (no flag) is
 * write-and-pass so a developer just re-runs the test to refresh the spec.
 *
 * <p>Mirrors {@link ModBffApplicationTest}: same {@code test} profile (in-mem H2 +
 * Liquibase disabled, so no real datastore is dialed) and a mocked
 * {@link ReactiveJwtDecoder} (no live Casdoor issuer is contacted). The
 * {@code Accept: application/json} header on the request is MANDATORY — springdoc-webflux's
 * openApiResource only renders the spec for the JSON media type; a default wildcard
 * Accept falls through to an empty {@code {}} body.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ActiveProfiles("test")
class OpenApiSpecDumpTest {

    /** Committed spec path (repo-relative; the test runs with cwd = module root). */
    private static final Path SPEC_PATH = Path.of("src", "main", "resources", "openapi", "openapi.json");

    private static final ObjectMapper STABLE_MAPPER = new ObjectMapper()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .enable(SerializationFeature.INDENT_OUTPUT);

    @Autowired WebTestClient client;

    /** No live Casdoor issuer in CI — mock the reactive JWT decoder so the oauth2
     *  resource-server wiring is satisfied without a network call (matches the
     *  context-load smoke test {@link ModBffApplicationTest}). */
    @MockitoBean ReactiveJwtDecoder jwtDecoder;

    @Test
    void dumpsDeterministicOpenApiSpec() throws Exception {
        // The Accept: application/json header is REQUIRED. springdoc-webflux's
        // openApiResource only renders the spec for the JSON media type; a default
        // (*/*) Accept falls through to an empty `{}` text/plain body.
        String raw = client.get().uri("/v3/api-docs")
                .accept(MediaType.APPLICATION_JSON)
                .exchange()
                .expectStatus().isOk()
                .expectBody(String.class)
                .returnResult()
                .getResponseBody();

        assertThat(raw).as("springdoc must serve a non-empty /v3/api-docs").isNotBlank();

        // Re-serialize with sorted keys + indentation so the on-disk form is stable
        // across runs/JVMs (springdoc's own key order is not guaranteed).
        JsonNode tree = STABLE_MAPPER.readTree(raw);
        String stable = STABLE_MAPPER.writeValueAsString(tree) + "\n";

        // Sanity: the document must describe the BFF surface, not an empty shell.
        assertThat(tree.path("openapi").asText()).startsWith("3.");
        assertThat(tree.path("paths").fieldNames())
                .toIterable()
                .as("the mod BFF surface must be present in the dumped spec")
                .anyMatch(p -> p.startsWith("/bff/mod"));

        boolean checkOnly = Boolean.getBoolean("openapi.spec.check");
        if (checkOnly) {
            assertThat(Files.exists(SPEC_PATH))
                    .as("committed spec %s must exist when -Dopenapi.spec.check=true", SPEC_PATH)
                    .isTrue();
            String committed = Files.readString(SPEC_PATH, StandardCharsets.UTF_8);
            assertThat(committed)
                    .as("committed %s is STALE — re-run `./mvnw -Dtest=OpenApiSpecDumpTest test` "
                            + "(without -Dopenapi.spec.check) and commit the refreshed spec", SPEC_PATH)
                    .isEqualTo(stable);
            return;
        }

        Files.createDirectories(SPEC_PATH.getParent());
        Files.writeString(SPEC_PATH, stable, StandardCharsets.UTF_8);
    }
}
