package net.hugmesh.modbff.federation;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.ConfigurationProperties;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

/**
 * OUTBOUND (client-side) mTLS for the reactive WebClient this BFF uses to call our
 * internal Java APIs (notably hugmesh-federation-api). When federation-api flips
 * its server-side {@code client-auth=need}, the handshake only completes if the
 * CALLER presents a certificate that chains to the cluster CA. This helper builds a
 * reactor-netty {@link HttpClient} carrying:
 *
 * <ul>
 *   <li>this BFF's PKI CLIENT IDENTITY — the PKCS12 {@code keystore.p12} (the same
 *       Vault/ESO-issued identity the server-side mTLS PR mounts), presented as the
 *       client cert on the handshake; and</li>
 *   <li>the cluster-CA TRUSTSTORE — the PKCS12 {@code truststore.p12}, so the BFF
 *       trusts the federation-api server cert (also chained to the cluster CA).</li>
 * </ul>
 *
 * <p>It deliberately REUSES the same {@code SSL_*} env / property names the
 * server-side mTLS PR introduced ({@code SSL_KEY_STORE}, {@code SSL_KEY_STORE_PASSWORD},
 * {@code SSL_TRUST_STORE}, {@code SSL_TRUST_STORE_PASSWORD}, all PKCS12) so the
 * deployment configures one set of stores for both directions.
 *
 * <p>GATED, DEFAULT OFF: {@code hugmesh.mtls.client.enabled=false}. Local/dev/CI
 * (plain http, no stores mounted) is unaffected — the WebClient is left on its
 * default connector. In-cluster the deployment sets {@code HUGMESH_MTLS_CLIENT_ENABLED=true}
 * alongside the server-side {@code SSL_CLIENT_AUTH=need}.
 */
@ConfigurationProperties(prefix = "hugmesh.mtls.client")
public class FederationHttpClientSsl {

    private static final Logger log = LoggerFactory.getLogger(FederationHttpClientSsl.class);

    /** Master gate — when false, no SSL is applied and the default connector is kept. */
    private boolean enabled = false;
    /** PKCS12 keystore holding THIS BFF's PKI client identity (cert + key). */
    private String keyStore = "/stores/keystore.p12";
    private String keyStorePassword = "";
    private String keyStoreType = "PKCS12";
    /** PKCS12 truststore holding the cluster CA (to trust the target's server cert). */
    private String trustStore = "/stores/truststore.p12";
    private String trustStorePassword = "";
    private String trustStoreType = "PKCS12";

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getKeyStore() { return keyStore; }
    public void setKeyStore(String keyStore) { this.keyStore = keyStore; }
    public String getKeyStorePassword() { return keyStorePassword; }
    public void setKeyStorePassword(String keyStorePassword) { this.keyStorePassword = keyStorePassword; }
    public String getKeyStoreType() { return keyStoreType; }
    public void setKeyStoreType(String keyStoreType) { this.keyStoreType = keyStoreType; }
    public String getTrustStore() { return trustStore; }
    public void setTrustStore(String trustStore) { this.trustStore = trustStore; }
    public String getTrustStorePassword() { return trustStorePassword; }
    public void setTrustStorePassword(String trustStorePassword) { this.trustStorePassword = trustStorePassword; }
    public String getTrustStoreType() { return trustStoreType; }
    public void setTrustStoreType(String trustStoreType) { this.trustStoreType = trustStoreType; }

    /**
     * Whether outbound client-presentation mTLS should be applied. True only when the
     * gate is on AND the identity keystore file is actually present (so a misconfigured
     * pod degrades to plain http rather than crashing on boot, and local/test never
     * touches the filesystem).
     */
    public boolean shouldApply() {
        if (!enabled) return false;
        boolean present = keyStore != null && Files.exists(Path.of(keyStore));
        if (!present) {
            log.warn("[mtls-client] enabled but key-store '{}' is absent — outbound mTLS NOT applied", keyStore);
        }
        return present;
    }

    /**
     * Decorate a reactor-netty {@link HttpClient} with the client-identity keystore +
     * cluster-CA truststore when {@link #shouldApply()}; otherwise return it unchanged.
     */
    public HttpClient customize(final HttpClient httpClient) {
        if (!shouldApply()) return httpClient;
        try {
            SslContext ssl = buildSslContext();
            log.info("[mtls-client] outbound client-cert presentation ENABLED (key-store={}, trust-store={})",
                    keyStore, trustStore);
            return httpClient.secure(spec -> spec.sslContext(ssl));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build outbound mTLS SslContext from "
                    + keyStore + " / " + trustStore, e);
        }
    }

    /** Build the client {@link SslContext}: key-manager = client identity, trust-manager = cluster CA. */
    SslContext buildSslContext() throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(load(keyStore, keyStoreType, keyStorePassword), pw(keyStorePassword));

        SslContextBuilder builder = SslContextBuilder.forClient().keyManager(kmf);
        // Trust manager (cluster CA) is optional: if no truststore is mounted, fall back
        // to the JVM default trust — but in-cluster the deployment always mounts it.
        if (trustStore != null && Files.exists(Path.of(trustStore))) {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(load(trustStore, trustStoreType, trustStorePassword));
            builder.trustManager(tmf);
        }
        return builder.build();
    }

    private static KeyStore load(String path, String type, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance(type == null ? "PKCS12" : type);
        try (InputStream in = Files.newInputStream(Path.of(path))) {
            ks.load(in, pw(password));
        }
        return ks;
    }

    private static char[] pw(String password) {
        return password == null ? new char[0] : password.toCharArray();
    }
}
