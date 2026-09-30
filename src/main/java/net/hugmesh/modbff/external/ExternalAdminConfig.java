package net.hugmesh.modbff.external;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

/**
 * Wires the reactive {@link MastodonAdminClient} (akkoma) on its own {@link WebClient}
 * pointed at the in-cluster homeserver (base URL defaults to the in-cluster service DNS
 * grounded in the hugmesh-generator manifests, akkoma :4000, overridable per env), plus
 * the {@link MatrixAdminClient} (tuwunel). The akkoma (Mastodon) leg is WIRED to the
 * confirmed pleroma-admin verbs. The tuwunel (Matrix) leg issues no HTTP at all: its only
 * verb is the instance block, recorded as a REQUEST because tuwunel has no runtime
 * federation-block verb, and its one-way user deactivate moved to hugmesh-admin-bff-api
 * (decision 83b, hugmesh-mod-bff-api#23), so it needs no WebClient, base URL, server name
 * or admin room. The {@code external.matrix.base-url} / {@code server-name} /
 * {@code admin-room} keys stay in {@code application.yml} but nothing here reads them.
 * Both {@code enabled} flags default false so a homeserver-less dev/test run boots
 * clean and merging is inert. Admin bearers are sourced from Vault via ESO —
 * {@code external.mastodon.admin-token} from {@code hugmesh/akkoma-admin},
 * {@code external.matrix.admin-token} from {@code hugmesh/tuwunel-admin} (ESO secret
 * {@code tuwunel-admin}, the same one the tuwunel-admin-sync Job mounts) — placeholder
 * /empty defaults here, never inlined; a blank token degrades (never OK) rather than
 * issuing an unauthenticated call.
 */
@Configuration(proxyBeanMethods = false)
public class ExternalAdminConfig {

    @Bean
    MatrixAdminClient matrixAdminClient(
            @Value("${external.matrix.enabled:false}") boolean enabled,
            // tuwunel-admin token from Vault hugmesh/tuwunel-admin (property "token") via ESO
            // secret tuwunel-admin — placeholder/empty default, never inlined. Only its
            // presence is checked (blank => degraded:no-admin-token); nothing is sent with it.
            @Value("${external.matrix.admin-token:}") String adminToken) {
        return new MatrixAdminClient(enabled, adminToken);
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
