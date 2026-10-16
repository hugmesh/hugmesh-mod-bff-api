package net.hugmesh.modbff.admin;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import net.hugmesh.modbff.federation.BearerForwardingFilter;
import net.hugmesh.modbff.federation.FederationHttpClientSsl;
import net.hugmesh.modbff.federation.SessionExchangeService;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Wires the {@link AdminSuspensionClient} on a reactive {@link WebClient} pointed at
 * hugmesh-admin-bff-api. The base URL defaults to the in-cluster service DNS
 * ({@code admin-bff.base-url}) and is overridable per env (never hardcoded without a
 * default). The MOD ban/lift write goes here — admin-bff owns the access_suspension
 * desired-state + the single-writer reconcile loop.
 *
 * <p>It REUSES the same {@link FederationHttpClientSsl} client-presentation machinery
 * the federation WebClient uses (the in-flight mTLS work), so flipping mTLS on for
 * this outbound leg is config-only ({@code hugmesh.mtls.client.enabled=true} +
 * the mounted PKCS12 stores) — no new SSL code. The caller's Casdoor bearer is also
 * forwarded so admin-bff sees the real principal; the cross-service ban authorisation
 * stays enforced at mod-bff's own service gate + the gateway route rules.
 */
@Configuration(proxyBeanMethods = false)
public class AdminApiConfig {

    @Bean
    WebClient adminBffWebClient(
            WebClient.Builder builder,
            FederationHttpClientSsl mtls,
            @Value("${admin-bff.base-url:http://hugmesh-admin-bff-api.hugmesh-backend.svc.cluster.local:8080}")
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
    AdminSuspensionClient adminSuspensionClient(WebClient adminBffWebClient) {
        return new AdminSuspensionClient(adminBffWebClient);
    }

    /**
     * Domain-lock desired-state writer. Reuses the SAME mTLS + bearer-forwarding
     * {@code adminBffWebClient} as the suspension client — domain-lock is the
     * ADD-semantics sibling of suspension, writing a SEPARATE admin-bff
     * {@code domain_lock} table via {@code /bff/admin/domain-lock/{role}/{user}}.
     */
    @Bean
    AdminDomainLockClient adminDomainLockClient(WebClient adminBffWebClient) {
        return new AdminDomainLockClient(adminBffWebClient);
    }

    /**
     * Read-only Casdoor role lookup for the non-privileged target guard (a MOD may not
     * ban a ROLE_ADMIN/ROLE_MOD). GATED behind {@code casdoor.admin.enabled} (default
     * false) so a Casdoor-less dev/CI run boots clean; in-cluster the deployment sets
     * the flag + the client credentials. HTTP Basic on every call, mirroring the
     * admin-bff {@code CasdoorAdminClient} transport (it reaches Casdoor THROUGH the
     * hugmesh-pki gateway).
     */
    @Bean
    CasdoorRoleClient casdoorRoleClient(
            WebClient.Builder builder,
            @Value("${casdoor.gateway-base:http://hugmesh-pki-gateway.hugmesh-pki.svc.cluster.local:8080}")
            String gatewayBase,
            @Value("${casdoor.organization:hugmesh}") String organization,
            @Value("${casdoor.client-id:}") String clientId,
            @Value("${casdoor.client-secret:}") String clientSecret,
            @Value("${casdoor.admin.enabled:false}") boolean enabled,
            // Per-brand domain→Casdoor-org map for the cross-domain moderation guard:
            // the privileged-target + same-tenant lookups key off the CALLER's brand org,
            // not the single static one. Empty = single-tenant (everyone uses the static
            // org). Format: comma-separated domain=org pairs (mirrors app.tenancy.issuers).
            @Value("${casdoor.org-map:}") String orgMapCsv) {
        WebClient http = builder
                .baseUrl(gatewayBase)
                .defaultHeader("Authorization", "Basic "
                        + Base64.getEncoder().encodeToString(
                                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8)))
                .build();
        return new CasdoorRoleClient(http, organization, enabled, parseOrgMap(orgMapCsv));
    }

    /** Parse a {@code domain=org,domain2=org2} CSV into a domain→org map. Blank/malformed
     *  pairs are skipped so a misconfig can never silently widen scope. */
    static Map<String, String> parseOrgMap(String csv) {
        Map<String, String> out = new LinkedHashMap<>();
        if (csv == null || csv.isBlank()) return out;
        for (String pair : csv.split(",")) {
            int eq = pair.indexOf('=');
            if (eq <= 0) continue;
            String domain = pair.substring(0, eq).trim();
            String org = pair.substring(eq + 1).trim();
            if (!domain.isEmpty() && !org.isEmpty()) out.put(domain, org);
        }
        return out;
    }
}
