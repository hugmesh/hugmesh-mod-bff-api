package net.hugmesh.modbff.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * Minimal OpenAPI document metadata for the moderator BFF spec served by
 * springdoc-openapi-starter-webflux-ui at {@code /v3/api-docs}.
 *
 * <p>Sets a stable {@code info.title} (the service name) + {@code info.version} so
 * the generated artefacts downstream are sensibly named: the platform
 * ng-openapi-gen typed clients, the paired hugmesh-mod-ui federated module, and
 * the docs pipeline all key off these fields. A programmatic {@link OpenAPI} bean
 * is used (rather than the {@code @OpenAPIDefinition} annotation) so the metadata
 * is plain bean wiring — no annotation reflection scan, which keeps the GraalVM
 * native build hint surface minimal.
 */
@Configuration(proxyBeanMethods = false)
public class OpenApiConfig {

    @Bean
    OpenAPI modBffOpenApi() {
        return new OpenAPI()
                // Pin a single relative-root server so the dumped spec is DETERMINISTIC:
                // springdoc (Boot 4 / springdoc 3.x) otherwise resolves the live server URL,
                // which under @SpringBootTest(RANDOM_PORT) is http://localhost:<random> and
                // would make the committed openapi.json change every run. An empty url keeps
                // the generated clients root-relative (the prior Boot-3 dump behaviour).
                .servers(List.of(new Server().url("")))
                .info(new Info()
                        .title("hugmesh-mod-bff-api")
                        .version("0.1.0")
                        .description("Moderator BFF API (/bff/mod/**) — federation moderation "
                                + "triage + refer-to-admin escalation, server-wide "
                                + "Matrix/Mastodon block (locally audited), and MOD-accessible "
                                + "federation module delivery. ROLE_MOD / ROLE_ADMIN only; no "
                                + "infra/server-admin surface."));
    }
}
