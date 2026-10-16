# Multi-issuer security-slice — the moderator-BFF replica

This repo replicates the **reference multi-issuer security-slice pattern** first built
in [`hugmesh-gateway`](https://github.com/hugmesh/hugmesh-gateway). The slice proves that
this Spring WebFlux OAuth2 resource server handles **per-brand (multi-issuer) Casdoor
tokens** correctly. An **unknown issuer fails CLOSED (401)**; it gets no benefit of the
doubt. A token from one brand can **never authenticate as another**.

The tests need **no network and no live Casdoor**. A tiny in-process HTTP server bound to
`127.0.0.1` serves each brand's JWKS and OIDC discovery doc, so
`ReactiveJwtDecoders.fromIssuerLocation(...)` validates real RSA-signed tokens offline.

---

## What the slice asserts

### Multi-issuer (`MultiIssuerSecuritySliceTest`)

| # | Scenario | Expectation | Category |
|---|----------|-------------|----------|
| (a) | A brand-X-issuer JWT | resolves to brand-X's manager → **authenticated**, and `DOMAIN_brandx` is emitted | USER-SITUATIONAL |
| (b) | A token from an issuer **not** in `app.tenancy.issuers` (well-formed, correctly signed, just unlisted) | the per-issuer resolver returns `Mono.empty()` → **401 fail-closed**, never a default-accept | CROSS-USER DENY |
| (c) | A brand-Y JWT presented to the resource server | scoped to brand-Y; can **never** become brand-X (no `DOMAIN_brandx`) | CROSS-USER DENY |

Three cheap fail-closed cases come with it. A **tampered signature** and a **garbage
bearer** both get 401. A **reserved-prefix authority-injection guard** stops a brand-Y token
with `permissions:["DOMAIN_brandx","ROLE_SUPERADMIN"]` from forging tenant scope or a
super-role.

### Coarse path-gate (`SecurityConfigPathGateSliceTest`)

This test drives the mod-BFF's `authorizeExchange` policy through the REAL prod chain
(`@Profile("!dev & !test")`):

- `/bff/mod/**` → `hasAnyRole(MOD,ADMIN,SUPERADMIN)`. MOD, ADMIN and SUPERADMIN are
  **ALLOWED**. A plain `ROLE_USER` token gets **403** (authenticated, not authorized).
  Anonymous gets 401.
- OpenAPI spec + Swagger UI (`/v3/api-docs/**`, `/swagger-ui/**`, `/swagger-ui.html`,
  `/webjars/swagger-ui/**`) → the prod chain gates them to `ADMIN,SUPERADMIN`. USER and MOD
  get 403, ADMIN and SUPERADMIN are ALLOWED, anonymous gets 401.
- `/actuator/health`, `/actuator/health/**`, `/actuator/info` → **public** (anonymous ALLOW).
- `anyExchange().authenticated()` floor: anonymous on a gated path → 401.
- **Single-issuer wiring decision**: one configured issuer and an empty
  `app.tenancy.issuers` give `isMultiIssuer()==false`. The chain stays on the plain
  `o.jwt(...)` decoder and never takes the multi-issuer swap.

> The mod-BFF's `SecurityConfig` declares a `roleHierarchy` bean, so `ROLE_SUPERADMIN`
> reaches the `@PreAuthorize("hasAnyRole('MOD','ADMIN')")` method gates. This slice builds
> the filter chain directly, without Spring's DI, so no `RoleHierarchy` bean takes part in
> the matchers. (The slice passes `roleHierarchy()` only to the step-up denial handler,
> which picks the body of a 403.) A `RoleHierarchy` bean is not auto-applied to
> `authorizeExchange` matchers in any case, only to `@PreAuthorize`. So
> `hasAnyRole("MOD","ADMIN","SUPERADMIN")` here matches ONLY the literal authorities the
> Casdoor converter emits, with no implied-role widening. The slice asserts each role
> literally.

---

## The two reusable seams

### 1. `TestIssuer` — mint issuer-specific JWTs against test JWKs (no network)

`src/test/java/net/hugmesh/modbff/testsupport/TestIssuer.java`. It is a copy of the
gateway's class with only the package changed. The gateway's copy has since gained
`mintExpired`; this one has not. Each instance generates a fresh RSA keypair and starts a
JDK `HttpServer` on `127.0.0.1:<random-port>`, which serves
`/.well-known/openid-configuration` and `/.well-known/jwks.json`. It exposes
`issuerUri()`, `mint(subject, roleNames)` and `mintWithClaims(subject, claims)`. A token
minted by issuer A is cryptographically valid **only** against issuer A's manager. That is
the cross-brand isolation. `TestIssuer` is `AutoCloseable` and is stopped in `@AfterEach`.
Its only dependency is `nimbus-jose-jwt`, already transitive via
`spring-boot-starter-oauth2-resource-server`.

### 2. `SecuritySliceSupport` — build the REAL filter chain into a `WebTestClient`

`src/test/java/net/hugmesh/modbff/config/SecuritySliceSupport.java`. It constructs this
repo's real `SecurityConfig(...).filterChain(...)`, the prod chain.

- The constructor also takes the D8 MFA `enabled`/`freshness-window` pair, which the slice
  pins to `false`/`600000L`.
- `filterChain` also takes the step-up access-denied handler. The slice builds it as the
  `@Bean` method does, with the step-up gate off, so it passes every refusal through.

The support class wraps the chain in a `WebFilterChainProxy` and installs it as a
`webFilter` on `WebTestClient.bindToController(...)`. There is **no full Spring Boot
context**. The production `authorizeExchange` policy and OAuth2 resource-server wiring run
exactly as deployed. Helpers: `provider(resolver)` takes the multi-issuer swap, and
`absent()` takes the single-issuer `o.jwt(...)` path.

---

## Why fail-closed is the load-bearing assertion

The per-issuer resolver's allowlist is exactly `DomainRegistry.trustedIssuers()`. An `iss`
outside that set gets **no** authentication manager, so the
`JwtIssuerReactiveAuthenticationManagerResolver` returns a 401 **before any authority is
emitted**. No fallback "default" manager exists that could accept an unlisted brand.
Scenario (b) is the regression guard. A refactor that adds a default-accept, or routes an
unknown `iss` to brand-X's manager, turns (b) red.
