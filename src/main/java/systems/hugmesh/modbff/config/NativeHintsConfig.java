package systems.hugmesh.modbff.config;

import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportRuntimeHints;
import systems.hugmesh.modbff.audit.ModAction;
import systems.hugmesh.modbff.federation.FederationManifestDto;
import systems.hugmesh.modbff.federation.ModerationRequestDto;
import systems.hugmesh.modbff.federation.SubmitModerationRequest;
import systems.hugmesh.modbff.service.ModService;
import systems.hugmesh.modbff.web.BanRequest;

/**
 * GraalVM native-image / AOT reachability hints for the bits the static analyzer
 * cannot see through on its own — mirrors hugmesh-admin-bff-api / actions /
 * gateway {@code NativeHintsConfig}.
 *
 * <p>Spring Boot's own AOT processing covers the framework surface (the WebFlux
 * WebClient codecs, the reactive OAuth2 resource-server JWT pipeline, R2DBC, and
 * the Jackson auto-configuration). What it cannot always infer:
 *
 * <ul>
 *   <li><b>JSON-bound DTOs</b> reached reflectively through Jackson — the records
 *       crossing the HTTP boundary to/from federation-api
 *       ({@link ModerationRequestDto}, {@link SubmitModerationRequest},
 *       {@link FederationManifestDto} + its nested remote record) and the audit
 *       record {@link ModAction} the controller serialises back. These typed
 *       records need explicit binding hints so their constructors/accessors survive
 *       native image.</li>
 *   <li><b>The springdoc Swagger UI webjar resources</b> — the
 *       {@code springdoc-openapi-starter-webflux-ui} starter serves the Swagger UI
 *       static assets out of {@code META-INF/resources/webjars/swagger-ui/}.
 *       native-image strips classpath resources by default, so the bundled
 *       {@code swagger-config} / {@code index.html} 404 without an explicit
 *       resource-include pattern. The raw {@code /v3/api-docs} JSON (what
 *       ng-openapi-gen + the docs pipeline actually consume) is produced by
 *       springdoc's own AOT-covered beans and does not need the webjar.</li>
 * </ul>
 *
 * <p>Best-effort: a full {@code -Pnative native:compile} on a GraalVM-equipped host
 * is the authoritative check; {@code add-reachability-metadata} (from the parent's
 * {@code native} profile) supplies the library-side metadata for the
 * WebClient/Netty/Jackson/r2dbc jars on top of these app-specific hints.
 */
@Configuration(proxyBeanMethods = false)
@ImportRuntimeHints(NativeHintsConfig.Hints.class)
public class NativeHintsConfig {

    static class Hints implements RuntimeHintsRegistrar {
        @Override
        public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
            hints.reflection()
                    .registerType(ModerationRequestDto.class, dtoCategories())
                    .registerType(SubmitModerationRequest.class, dtoCategories())
                    .registerType(FederationManifestDto.class, dtoCategories())
                    .registerType(FederationManifestDto.FederationRemoteDto.class, dtoCategories())
                    .registerType(ModAction.class, dtoCategories())
                    // Phase-2 ban surface: the request body Jackson binds + the result
                    // record the controller serialises in the 202 pending body.
                    .registerType(BanRequest.class, dtoCategories())
                    .registerType(ModService.BanResult.class, dtoCategories());

            // Swagger UI static assets shipped inside the springdoc webflux-ui
            // starter's webjar. native-image drops classpath resources unless
            // explicitly included; without this the Swagger UI page 404s its own
            // bundle under a native binary. The /v3/api-docs JSON (the artefact
            // ng-openapi-gen + the docs pipeline consume) is bean-produced and
            // unaffected, so the spec stays available regardless.
            hints.resources()
                    .registerPattern("META-INF/resources/webjars/swagger-ui/*")
                    .registerPattern("META-INF/resources/webjars/swagger-ui/**");
        }

        private static MemberCategory[] dtoCategories() {
            return new MemberCategory[] {
                    MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
                    MemberCategory.INVOKE_DECLARED_METHODS,
                    MemberCategory.ACCESS_DECLARED_FIELDS,
            };
        }
    }
}
