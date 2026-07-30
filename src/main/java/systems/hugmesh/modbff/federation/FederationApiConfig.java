package systems.hugmesh.modbff.federation;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

/**
 * Wires the {@link FederationApiClient} on a reactive {@link WebClient} pointed at
 * the in-cluster federation-api with the caller's-bearer forwarding filter. The
 * base URL has a sensible in-cluster default ({@code federation-api.base-url}) so
 * the BFF boots without extra config in the cluster, and is overridable per env —
 * the contract said NOT to hardcode without a default.
 *
 * <p>When {@code hugmesh.mtls.client.enabled=true} (default OFF), the WebClient is
 * given a reactor-netty connector that presents this BFF's PKI client identity and
 * trusts the cluster CA, so federation-api's {@code client-auth=need} handshake
 * succeeds. See {@link FederationHttpClientSsl}.
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(FederationHttpClientSsl.class)
public class FederationApiConfig {

    @Bean
    WebClient federationWebClient(
            WebClient.Builder builder,
            FederationHttpClientSsl mtls,
            @Value("${federation-api.base-url:http://hugmesh-federation-api.hugmesh-backend.svc.cluster.local:8080}")
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
    FederationApiClient federationApiClient(WebClient federationWebClient) {
        return new FederationApiClient(federationWebClient);
    }
}
