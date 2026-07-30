package systems.hugmesh.modbff.owncast;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import systems.hugmesh.modbff.federation.BearerForwardingFilter;
import systems.hugmesh.modbff.federation.FederationHttpClientSsl;
import systems.hugmesh.modbff.federation.SessionExchangeService;

/**
 * Wires the {@link OwncastModClient} on a reactive {@link WebClient} pointed at
 * hugmesh-owncast-bff-api. The base URL defaults to the in-cluster service DNS
 * ({@code owncast-bff.base-url}) and is overridable per env (never hardcoded without
 * a default). The MOD hide/kill/restore effector calls go here — owncast-bff owns the
 * {@code owncast_grant}/{@code owncast_stream} moderation state + its local journal.
 *
 * <p>It REUSES the same {@link FederationHttpClientSsl} client-presentation machinery
 * the federation/admin-bff WebClients use, so flipping mTLS on for this outbound leg is
 * config-only ({@code hugmesh.mtls.client.enabled=true} + the mounted PKCS12
 * stores) — no new SSL code. The caller's Casdoor bearer is also forwarded so
 * owncast-bff sees the REAL moderator principal (and re-derives the brand from the
 * same validated issuer); the cross-service moderation authorisation stays enforced at
 * mod-bff's own service gate + owncast-bff's path gate + the gateway route rules.
 */
@Configuration(proxyBeanMethods = false)
public class OwncastApiConfig {

    @Bean
    WebClient owncastBffWebClient(
            WebClient.Builder builder,
            FederationHttpClientSsl mtls,
            @Value("${owncast-bff.base-url:http://hugmesh-owncast-bff-api.hugmesh-backend.svc.cluster.local:8080}")
            String baseUrl,
            ObjectProvider<SessionExchangeService> sessionExchangeServiceProvider) {
        HttpClient httpClient = mtls.customize(HttpClient.create());
        return builder
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .filter(BearerForwardingFilter.forwardCallerToken(sessionExchangeServiceProvider))
                .build();
    }

    @Bean
    OwncastModClient owncastModClient(WebClient owncastBffWebClient) {
        return new OwncastModClient(owncastBffWebClient);
    }
}
