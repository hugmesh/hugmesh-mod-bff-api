# Security — hugmesh-mod-bff-api

## Authentication layers

Two independent layers protect this BFF.

1. **Application-layer authentication.** Every request, except the `/actuator/health` and
   `/actuator/info` probes, must carry one of two credentials.
   - A valid Casdoor-issued JWT (`spring.security.oauth2.resourceserver`). The BFF
     re-validates the forwarded bearer and passes it on to federation-api, admin-bff and
     owncast-bff, so each of them authorises the original moderator.
   - For a native-login caller, an opaque `bff_` session, sent as a cookie or as an
     `Authorization: Bearer bff_...` header. `BffCookieAuthenticationWebFilter` resolves it
     against admin-bff-api's `GET /bff/internal/session/introspect` before the
     resource-server chain runs. If admin-bff is unreachable, the request fails closed with
     `503`. A suspended or banned account gets an explicit `403`. The README section
     *Native-login (`bff_` session) support* has the full contract.

2. **Mutual TLS, the API-to-API trust boundary (transport layer).** In-cluster, the TLS
   handshake **requires a client certificate that chains to the cluster CA truststore**.
   Only services deployed and signed by our Vault/ESO PKI process hold such a certificate.
   A random pod, an external client, or anything else not issued by our PKI presents no
   chaining certificate. Its handshake is rejected before any byte of HTTP is read, so it
   cannot read or call this API at all.

## How the mTLS layer is wired

The cluster CA is the offline root from `hugmesh-generator/scripts/gen-keystores.sh`.
In-cluster, Vault PKI imports that CA and issues a short-lived leaf cert per app
(`pki_int/issue/hugmesh-mod-bff-api`, TTL 720h). External Secrets Operator (ESO) syncs the
cert into the `hugmesh-mod-bff-api-mtls` `kubernetes.io/tls` Secret (`tls.crt` / `tls.key` /
`ca.crt`). A keystore initContainer (the equivalent of the gateway chart's `build-keystore`)
assembles two files:

- `keystore.p12` — this service's own mTLS **identity** (key + cert chain),
- `truststore.p12` — the **cluster CA** trust anchor.

It writes them to an in-pod tmpfs and generates the store password there. The password
never enters git, a Secret, or Vault. The deployment sets the env described below, and the
running pod then enforces client-cert verification. Every in-cluster leaf chains to the
same cluster CA, so the truststore validates them all. ESO re-issues the cert every 168h
(`refreshInterval`). The initContainer builds the stores once, at pod start.

The gateway (`hugmesh-fe-gateway`) is the legitimate caller. It presents its own ESO-issued
client cert when it proxies to this BFF (`specs/cluster/apps/20-gateway-fe.yaml` sets
`HUGMESH_GATEWAY_MTLS_ENABLED=true`). Its handshake succeeds; everyone else's fails.

## Configuration (parameterized — safe by default)

`server.ssl.*` in `application.yml` is parameterized so local, dev and CI keep working:

| Property | Env var | Local/CI default | In-cluster value |
| --- | --- | --- | --- |
| `server.ssl.enabled` | `SSL_ENABLED` | `false` (plaintext) | `true` |
| `server.ssl.client-auth` | `SSL_CLIENT_AUTH` | `none` | `need` |
| `server.ssl.key-store` | `SSL_KEY_STORE` | `/stores/keystore.p12` | mounted PKCS12 keystore |
| `server.ssl.key-store-type` | `SSL_KEY_STORE_TYPE` | `PKCS12` | `PKCS12` |
| `server.ssl.key-store-password` | `SSL_KEY_STORE_PASSWORD` | _(empty)_ | in-pod-generated, set through `/stores/application.properties` |
| `server.ssl.trust-store` | `SSL_TRUST_STORE` | `/stores/truststore.p12` | mounted PKCS12 truststore (cluster CA) |
| `server.ssl.trust-store-type` | `SSL_TRUST_STORE_TYPE` | `PKCS12` | `PKCS12` |
| `server.ssl.trust-store-password` | `SSL_TRUST_STORE_PASSWORD` | _(empty)_ | in-pod-generated, set through `/stores/application.properties` |
| `server.ssl.enabled-protocols` | `SSL_ENABLED_PROTOCOLS` | `TLSv1.3` | `TLSv1.3` |

With the defaults, `server.ssl.enabled=false`. The stores are never opened and the existing
tests run unchanged. `client-auth` maps to Netty's `ClientAuth`: `none → NONE`,
`want → OPTIONAL`, `need → REQUIRE`. WebFlux/Netty reads these properties directly, so no
custom `SslContext`/`HttpServer` bean is needed.

## Deployment (owned by hugmesh-generator)

The deployment manifest for this BFF lives in `hugmesh-generator`
(`specs/cluster/manifests/mod-bff-api/deployment.yaml`), not in this repo. On `origin/main`
(checked 2026-10-07) it enforces the server side:

- a `build-keystore` initContainer, a `pki` volume (the `hugmesh-mod-bff-api-mtls` Secret)
  and a `stores` tmpfs volume, as in
  `specs/cluster/charts/hugmesh-gateway/templates/deployment.yaml`;
- the env `SSL_ENABLED=true`, `SSL_CLIENT_AUTH=need`, `SSL_KEY_STORE=/stores/keystore.p12`,
  `SSL_KEY_STORE_TYPE=PKCS12`, `SSL_TRUST_STORE=/stores/truststore.p12`,
  `SSL_TRUST_STORE_TYPE=PKCS12` and `SPRING_CONFIG_ADDITIONAL_LOCATION=file:/stores/`;
- store passwords that are not env vars. The initContainer writes
  `/stores/application.properties` with `server.ssl.key-store-password`,
  `server.ssl.trust-store-password` and the two `hugmesh.mtls.client.*` passwords. The file
  must be named `application.properties`. Spring loads a profile-named file from that
  directory only when that profile is active;
- exec probes that run `curl --cert /pki/tls.crt --key /pki/tls.key --cacert /pki/ca.crt`
  against `https://hugmesh-mod-bff-api:8080/actuator/health/{readiness,liveness}`. With
  `client-auth=need` a kubelet `httpGet` cannot present a client cert, so the handshake
  would fail.

This BFF is also an mTLS **client** of federation-api and admin-bff. That outbound
client-cert presentation is **already implemented** and config-gated.
`FederationHttpClientSsl` builds a reactor-netty connector that presents this BFF's
`keystore.p12` identity (and trusts the cluster CA) on its outbound calls. The gate is
`hugmesh.mtls.client.enabled` (env `HUGMESH_MTLS_CLIENT_ENABLED`, **default off**, so local,
dev and CI plaintext is unaffected). See the README section *API-to-API mTLS / Client side
(outbound)*. The follow-up is deployment-side only. The generator manifest leaves
`HUGMESH_MTLS_CLIENT_ENABLED` unset (off) and points `FEDERATION_API_BASE_URL` and
`ADMIN_BFF_BASE_URL` at `https://` hosts, so the generator must still enable the client
identity. This is independent of the server-side enforcement described above.
