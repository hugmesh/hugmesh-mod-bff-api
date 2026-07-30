package systems.hugmesh.modbff;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Moderator BFF — backend namespace, behind the be-gateway. The MODERATOR-scoped
 * (hasAnyRole MOD or ADMIN) Best-Friends-Forever pair of the future
 * {@code hugmesh-mod-ui}. It deliberately owns NO infrastructure /
 * server-admin surface: it
 *
 * <ul>
 *   <li>triages the federation moderation queue (reactive WebClient to
 *       hugmesh-federation-api {@code /api/federation/moderation});</li>
 *   <li>refers user-removal / instance-block recommendations UP to an admin
 *       (federation-api {@code /moderation/{id}/refer}) — a MOD never removes a
 *       user directly, escalation only;</li>
 *   <li>pushes server-wide Matrix(tuwunel)/Mastodon(akkoma) blocks — the
 *       external admin HTTP call is STUBBED (the homeserver admin shapes are
 *       unconfirmed, see README) but the action is recorded in the local R2DBC
 *       {@code mod_action} audit table;</li>
 *   <li>delivers the MOD-accessible federation modules (federation-api
 *       {@code /api/federation/manifest}).</li>
 * </ul>
 *
 * <p>Reactive throughout (WebFlux + R2DBC; JDBC only for Liquibase). The
 * Casdoor-issued JWT is validated by the resource-server filter chain
 * ({@code SecurityConfig}); the caller's bearer is forwarded to federation-api on
 * every call by a token-injecting {@code ExchangeFilterFunction}.
 */
@SuppressWarnings("checkstyle:HideUtilityClassConstructor")
@SpringBootApplication
public class ModBffApplication {
    public static void main(String[] args) {
        SpringApplication.run(ModBffApplication.class, args);
    }
}
