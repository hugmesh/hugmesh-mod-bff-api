# Multi-issuer security-slice — the moderator-BFF replica

This repo replicates the **reference multi-issuer security-slice pattern** first built
in [`hugmesh-gateway`](https://github.com/hugmesh/hugmesh-gateway). It proves this
Spring WebFlux OAuth2 resource server correctly handles **per-brand (multi-issuer)
Casdoor tokens**, with the security property that matters most: an **unknown issuer
fails CLOSED (401)** and a token from one brand can **never authenticate as another**.

The whole point is **determinism with no network and no live Casdoor**: each brand's
JWKS + OIDC discovery doc is served by a tiny in-process HTTP server bound to
`127.0.0.1`, so `ReactiveJwtDecoders.fromIssuerLocation(...)` validates real
RSA-signed tokens offline.

---

## What the slice asserts

### Multi-issuer (`MultiIssuerSecuritySliceTest`)

| # | Scenario | Expectation | Category |
|---|----------|-------------|----------|
| (a) | A brand-X-issuer JWT | resolves to brand-X's manager → **authenticated**, and `DOMAIN_brandx` is emitted | USER-SITUATIONAL |
| (b) | A token from an issuer **not** in `app.tenancy.issuers` (well-formed, correctly signed, just unlisted) | the per-issuer resolver returns `Mono.empty()` → **401 fail-closed**, never a default-accept | CROSS-USER DENY |
| (c) | A brand-Y JWT presented to the resource server | scoped to brand-Y; can **never** become brand-X (no `DOMAIN_brandx`) | CROSS-USER DENY |

Plus the cheap fail-closed neighbours: a **tampered signature** and a **garbage
bearer** both 401, and a **reserved-prefix authority-injection guard** (a brand-Y
`permissions:["DOMAIN_brandx","ROLE_SUPERADMIN"]` cannot forge tenant scope / super-role).

### Coarse path-gate (`SecurityConfigPathGateSliceTest`)

The mod-BFF's `authorizeExchange` policy, end-to-end through the REAL prod chain
(`@Profile("!dev & !test")`):

- `/bff/mod/**` → `hasAnyRole(MOD,ADMIN,SUPERADMIN)`: MOD/ADMIN/SUPERADMIN **ALLOW**; a
  plain `ROLE_USER` token → **403** (authenticated but not authorized); anonymous → 401.
- OpenAPI spec + Swagger UI (`/v3/api-docs/**`, `/swagger-ui/**`, `/swagger-ui.html`,
  `/webjars/swagger-ui/**`) → prod chain gates to
  `ADMIN,SUPERADMIN`: USER/MOD → 403, ADMIN/SUPERADMIN ALLOW, anonymous → 401.
- `/actuator/health`, `/actuator/health/**`, `/actuator/info` → **public** (anonymous ALLOW).
- `anyExchange().authenticated()` floor: anonymous on a gated path → 401.
- **Single-issuer wiring decision**: the lone configured issuer + empty
  `app.tenancy.issuers` ⇒ `isMultiIssuer()==false`, so the chain stays on the plain
  `o.jwt(...)` decoder and never takes the multi-issuer swap.

> The mod-BFF's `SecurityConfig` does declare a `roleHierarchy` bean (so
> `ROLE_SUPERADMIN` reaches the `@PreAuthorize("hasAnyRole('MOD','ADMIN')")` method
> gates), but this slice builds the filter chain directly, without Spring's DI, so no
> `RoleHierarchy` bean participates in the matchers (the slice does pass `roleHierarchy()`
> to the step-up denial handler, which only chooses the body of a 403) — and a
> `RoleHierarchy` bean is not auto-applied to
> `authorizeExchange` matchers in any case (only to `@PreAuthorize`). So
> `hasAnyRole("MOD","ADMIN","SUPERADMIN")` here matches ONLY the literal authorities the
> Casdoor converter emits — there is no implied-role widening for this coarse gate. Each
> role is asserted literally.

---

## The two reusable seams

### 1. `TestIssuer` — mint issuer-specific JWTs against test JWKs (no network)

`src/test/java/net/hugmesh/modbff/testsupport/TestIssuer.java`. Copied from the
gateway with only the package changed; the gateway's copy has since gained `mintExpired`,
this one has not. Each instance generates a fresh RSA keypair,
starts a JDK `HttpServer` on `127.0.0.1:<random-port>` serving
`/.well-known/openid-configuration` + `/.well-known/jwks.json`, and exposes
`issuerUri()` / `mint(subject, roleNames)` / `mintWithClaims(subject, claims)`. A token
minted by issuer A is cryptographically valid **only** against issuer A's manager — that
is the cross-brand isolation. `AutoCloseable`; stopped in `@AfterEach`. Only dependency
is `nimbus-jose-jwt`, already transitive via `spring-boot-starter-oauth2-resource-server`.

### 2. `SecuritySliceSupport` — build the REAL filter chain into a `WebTestClient`

`src/test/java/net/hugmesh/modbff/config/SecuritySliceSupport.java`. Constructs
this repo's real `SecurityConfig(...).filterChain(...)` (the prod chain — the
constructor also takes the D8 MFA `enabled`/`freshness-window` pair, both pinned to
`false`/`600000L` by the slice; `filterChain` also takes the step-up access-denied
handler, which the slice builds as the `@Bean` method does, with the step-up gate off, so
it passes every refusal through), wraps it in a `WebFilterChainProxy`, and installs it
as a `webFilter` on
`WebTestClient.bindToController(...)`. **No full Spring Boot context** — the production
`authorizeExchange` policy and OAuth2 resource-server wiring run exactly as deployed.
Helpers: `provider(resolver)` (take the multi-issuer swap) / `absent()` (single-issuer
`o.jwt(...)` path).

---

## Why fail-closed is the load-bearing assertion

The per-issuer resolver's allowlist is exactly `DomainRegistry.trustedIssuers()`. An
`iss` outside that set yields **no** authentication manager, so the
`JwtIssuerReactiveAuthenticationManagerResolver` surfaces a 401 **before any authority
is emitted** — there is no fallback "default" manager that could accept an unlisted
brand. Scenario (b) is the regression guard that keeps it that way: a future refactor
that introduces a default-accept (or routes an unknown `iss` to brand-X's manager) turns
(b) red.
