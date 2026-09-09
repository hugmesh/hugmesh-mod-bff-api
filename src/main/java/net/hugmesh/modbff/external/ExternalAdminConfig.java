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
 * the tuwunel (Matrix) leg is WIRED to the admin-room {@code !admin users deactivate}
 * command transport for block-user (posted, never ok — see {@link MatrixAdminClient}).
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
            WebClient.Builder builder,
            @Value("${external.matrix.base-url:http://tuwunel.hugmesh-backend.svc.cluster.local:8008}")
            String baseUrl,
            @Value("${external.matrix.enabled:false}") boolean enabled,
            // privileged admin-room member token from Vault hugmesh/tuwunel-admin (property
            // "token") via ESO secret tuwunel-admin — placeholder/empty default, never inlined.
            @Value("${external.matrix.admin-token:}") String adminToken,
            // the homeserver server_name (tuwunel.toml) — qualifies a bare localpart target.
            @Value("${external.matrix.server-name:hugmesh.net}") String serverName,
            // the admin room alias (tuwunel.toml admin_room_default), resolved + cached.
            @Value("${external.matrix.admin-room:#admins:hugmesh.net}") String adminRoom) {
        return new MatrixAdminClient(builder.baseUrl(baseUrl).build(), enabled, adminToken, serverName, adminRoom);
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
