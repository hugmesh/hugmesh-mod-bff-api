package net.hugmesh.modbff.federation;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import reactor.netty.http.client.HttpClient;

import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Asserts the OUTBOUND mTLS customization is APPLIED when the gate is on and a client
 * keystore is present, and SKIPPED (default connector untouched) when disabled or no
 * store exists. No real TLS handshake is performed — we only assert the
 * {@link HttpClient} instance is/ isn't decorated and that a client {@code SslContext}
 * can be built from a generated PKCS12 keystore.
 */
class FederationHttpClientSslTest {

    /** Write an empty (no-entry) PKCS12 keystore that loads cleanly for the test. */
    private static Path emptyP12(Path dir, String name, String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        Path p = dir.resolve(name);
        try (OutputStream out = Files.newOutputStream(p)) {
            ks.store(out, password.toCharArray());
        }
        return p;
    }

    @Test
    void disabled_byDefault_leavesHttpClientUntouched() {
        FederationHttpClientSsl mtls = new FederationHttpClientSsl();
        assertThat(mtls.isEnabled()).isFalse();
        assertThat(mtls.shouldApply()).isFalse();

        HttpClient base = HttpClient.create();
        assertThat(mtls.customize(base)).isSameAs(base);
    }

    @Test
    void enabled_butKeystoreAbsent_skipsAndKeepsDefaultConnector() {
        FederationHttpClientSsl mtls = new FederationHttpClientSsl();
        mtls.setEnabled(true);
        mtls.setKeyStore("/stores/does-not-exist.p12");

        assertThat(mtls.shouldApply()).isFalse();
        HttpClient base = HttpClient.create();
        assertThat(mtls.customize(base)).isSameAs(base);
    }

    @Test
    void enabled_withKeystorePresent_appliesSslAndReturnsNewClient(@TempDir Path dir) throws Exception {
        String pw = "changeit";
        Path ks = emptyP12(dir, "keystore.p12", pw);
        Path ts = emptyP12(dir, "truststore.p12", pw);

        FederationHttpClientSsl mtls = new FederationHttpClientSsl();
        mtls.setEnabled(true);
        mtls.setKeyStore(ks.toString());
        mtls.setKeyStorePassword(pw);
        mtls.setTrustStore(ts.toString());
        mtls.setTrustStorePassword(pw);

        assertThat(mtls.shouldApply()).isTrue();
        assertThat(mtls.buildSslContext().isClient()).isTrue();

        HttpClient base = HttpClient.create();
        HttpClient secured = mtls.customize(base);
        // .secure(...) returns a new, decorated HttpClient instance.
        assertThat(secured).isNotSameAs(base);
    }
}
