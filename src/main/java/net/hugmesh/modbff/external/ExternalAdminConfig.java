package net.hugmesh.modbff.external;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the reactive {@link MatrixAdminClient} (tuwunel) + {@link MastodonAdminClient}
 * (akkoma) on their own {@link WebClient}s pointed at the in-cluster homeservers.
 * Base URLs default to the in-cluster service DNS grounded in the
 * hugmesh-generator manifests (tuwunel :8008, akkoma :4000) and are overridable
 * per env. The akkoma (Mastodon) leg is WIRED to the confirmed pleroma-admin verbs;
 * the tuwunel (Matrix) leg stays a flag-gated structured stub (no HTTP admin API —
 * see {@link MatrixAdminClient}). Both {@code enabled} flags default false so a
 * homeserver-less dev/test run boots clean and merging is inert. The akkoma admin
 * bearer ({@code external.mastodon.admin-token}) is sourced from Vault
 * {@code hugmesh/akkoma-admin} property {@code token} via ESO — placeholder/empty
 * default here, never inlined; a blank token degrades (never OK) rather than issuing
 * an unauthenticated call.
 */
@Configuration(proxyBeanMethods = false)
public class ExternalAdminConfig {

    @Bean
    MatrixAdminClient matrixAdminClient(
            WebClient.Builder builder,
            @Value("${external.matrix.base-url:http://tuwunel.hugmesh-backend.svc.cluster.local:8008}")
            String baseUrl,
            @Value("${external.matrix.enabled:false}") boolean enabled) {
        return new MatrixAdminClient(builder.baseUrl(baseUrl).build(), enabled);
    }

    @Bean
    MastodonAdminClient mastodonAdminClient(
            WebClient.Builder builder,
            @Value("${external.mastodon.base-url:http://akkoma.hugmesh-backend.svc.cluster.local:4000}")
            String baseUrl,
            @Value("${external.mastodon.enabled:false}") boolean enabled,
            // akkoma admin bearer from Vault hugmesh/akkoma-admin (property "token")
            // via ESO — placeholder/empty default, never inlined. Blank => degraded, no call.
            @Value("${external.mastodon.admin-token:}") String adminToken) {
        return new MastodonAdminClient(builder.baseUrl(baseUrl).build(), enabled, adminToken);
    }
}
