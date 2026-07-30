package systems.hugmesh.modbff.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.netty.http.client.HttpClient;
import systems.hugmesh.modbff.federation.FederationHttpClientSsl;

/**
 * Wires a DEDICATED reactive {@link WebClient} + {@link AdminBffSessionIntrospectClient}
 * pointed at admin-bff-api's INTERNAL surface, for {@link BffCookieAuthenticationWebFilter}
 * to bridge an opaque {@code bff_} session into this service's OWN Spring Security
 * context (the same gap already closed for admin-bff-api itself — see
 * {@code BffCookieAuthenticationWebFilter}'s class doc).
 *
 * <p>Deliberately SEPARATE from {@link systems.hugmesh.modbff.admin.AdminApiConfig}'s
 * existing {@code adminBffWebClient} bean:
 * <ul>
 *   <li>{@code adminBffWebClient} forwards the CALLER's own Casdoor bearer
 *       ({@code BearerForwardingFilter.forwardCallerToken()}) against admin-bff's
 *       PUBLIC {@code /bff/admin/**} surface — it never carries an internal-token and
 *       is useless against {@code /bff/internal/**}, which is guarded by
 *       {@code InternalTokenWebFilter} (mTLS + constant-time {@code X-Internal-Token}
 *       compare) rather than a caller bearer.</li>
 *   <li>This bean instead stamps {@code X-Internal-Token} on every request (when
 *       configured — blank in dev/test/CI, matching {@code InternalTokenWebFilter}'s
 *       own non-enforcing-when-unset posture) and carries NO caller bearer at all: the
 *       "caller" of this endpoint is mod-bff-api itself, authenticating the bff_
 *       TOKEN, not forwarding a Casdoor JWT the caller may not even have.</li>
 * </ul>
 *
 * <p>Reuses the SAME outbound mTLS client-presentation ({@link FederationHttpClientSsl})
 * as {@code AdminApiConfig}/{@code FederationApiConfig} — config-only
 * ({@code hugmesh.mtls.client.enabled=true}) to present this BFF's PKI identity once
 * admin-bff-api requires client certs on this port too; local/dev/CI is unaffected
 * (plain http, no stores mounted).
 *
 * <p>{@code app.bff-session.*} intentionally reuses the SAME property namespace the
 * gateway's own {@code BffSessionConfig}/{@code BffSessionProperties} use for the
 * identical admin-bff introspection call, so one {@code INTERNAL_TOKEN} secret and one
 * mental model covers both services.
 */
@Configuration(proxyBeanMethods = false)
public class AdminBffSessionAuthConfig {

    @Bean
    WebClient adminBffInternalWebClient(
            WebClient.Builder builder,
            FederationHttpClientSsl mtls,
            @Value("${admin-bff.base-url:http://hugmesh-admin-bff-api.hugmesh-backend.svc.cluster.local:8080}")
            String baseUrl,
            @Value("${app.bff-session.internal-token:}") String internalToken,
            @Value("${app.bff-session.internal-token-header:X-Internal-Token}") String internalTokenHeader) {
        HttpClient httpClient = mtls.customize(HttpClient.create());
        WebClient.Builder configured = builder
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient));
        if (internalToken != null && !internalToken.isBlank()) {
            String header = (internalTokenHeader == null || internalTokenHeader.isBlank())
                    ? "X-Internal-Token" : internalTokenHeader;
            configured = configured.filter(stampInternalToken(header, internalToken));
        }
        return configured.build();
    }

    @Bean
    AdminBffSessionIntrospectClient adminBffSessionIntrospectClient(WebClient adminBffInternalWebClient) {
        return new AdminBffSessionIntrospectClient(adminBffInternalWebClient);
    }

    /** Stamp a fixed header (the internal-service credential) on every outgoing request. */
    private static ExchangeFilterFunction stampInternalToken(String header, String token) {
        return ExchangeFilterFunction.ofRequestProcessor(request ->
                Mono.just(ClientRequest.from(request)
                        .headers(h -> h.set(header, token))
                        .build()));
    }
}
