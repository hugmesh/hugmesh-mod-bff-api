package net.hugmesh.modbff.admin;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link CasdoorRoleClient} — the per-domain Casdoor reads behind the cross-domain
 * moderation guard (A01 BOLA/BFLA / CWE-639). Delineated per the test standard:
 *
 * <ul>
 *   <li>USER-SITUATIONAL — orgForDomain resolves the caller's brand org (or the static
 *       fallback); belongsToDomain confirms an in-org target; the disabled seam fails
 *       closed.</li>
 *   <li>CROSS-USER (the fix) — a target in a DIFFERENT brand's org is keyed off the
 *       CALLER's org, so the get-user resolves ABSENT → belongsToDomain false (deny);
 *       and a brand-X privileged read keys off brand-X's org, never the static one.</li>
 * </ul>
 */
class CasdoorRoleClientTest {

    /** Records outgoing requests + returns a canned JSON body per the request path. */
    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();
        /** id ("org/name") -> JSON body to return for get-user/get-role on that id. */
        final Map<String, String> bodyById;

        Recorder(Map<String, String> bodyById) {
            this.bodyById = bodyById;
        }

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            String id = request.url().getQuery() == null ? "" : request.url().getQuery();
            // query is id=<org>/<name> (possibly url-encoded '/')
            String key = id.startsWith("id=") ? id.substring(3).replace("%2F", "/") : id;
            String body = bodyById.getOrDefault(key, "{\"data\":null}");
            return Mono.just(ClientResponse.create(HttpStatus.OK)
                    .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                    .body(body).build());
        }
    }

    private WebClient web(Recorder rec) {
        return WebClient.builder().baseUrl("http://casdoor.test").exchangeFunction(rec).build();
    }

    // ── orgForDomain (USER-SITUATIONAL) ────────────────────────────────
    @Test
    void orgForDomain_mapsBrandDomainToItsOrg_elseStaticFallback() {
        CasdoorRoleClient c = new CasdoorRoleClient(
                web(new Recorder(Map.of())), "hugmesh", true,
                Map.of("brandx", "orgx", "brandy", "orgy"));
        assertThat(c.orgForDomain("brandx")).isEqualTo("orgx");
        assertThat(c.orgForDomain("brandy")).isEqualTo("orgy");
        // null / blank / 'default' single-tenant -> the static org.
        assertThat(c.orgForDomain(null)).isEqualTo("hugmesh");
        assertThat(c.orgForDomain("default")).isEqualTo("hugmesh");
        // an UNMAPPED branded domain falls back to the static org (never another brand).
        assertThat(c.orgForDomain("brandz")).isEqualTo("hugmesh");
    }

    // ── belongsToDomain ALLOW: target present in the caller's brand org ──
    @Test
    void belongsToDomain_targetInCallersOrg_isTrue_andKeysOffCallersOrg() {
        Recorder rec = new Recorder(Map.of(
                "orgx/alice", "{\"data\":{\"name\":\"alice\",\"owner\":\"orgx\"}}"));
        CasdoorRoleClient c = new CasdoorRoleClient(web(rec), "hugmesh", true,
                Map.of("brandx", "orgx"));
        StepVerifier.create(c.belongsToDomain("alice", "brandx"))
                .expectNext(true).verifyComplete();
        // The read was keyed off the CALLER's brand org (orgx), not the static org.
        assertThat(rec.requests).hasSize(1);
        assertThat(rec.requests.get(0).url().getPath()).isEqualTo("/api/get-user");
        assertThat(rec.requests.get(0).url().getQuery()).contains("orgx").contains("alice");
    }

    // ── belongsToDomain DENY (the fix): a cross-brand target resolves ABSENT ──
    @Test
    void belongsToDomain_crossBrandTarget_isFalse_failClosed() {
        // The recorder only knows brandY's org (orgy); keyed off brandX's org (orgx) the
        // get-user for orgx/victim returns data:null -> absent -> false.
        Recorder rec = new Recorder(Map.of(
                "orgy/victim", "{\"data\":{\"name\":\"victim\",\"owner\":\"orgy\"}}"));
        CasdoorRoleClient c = new CasdoorRoleClient(web(rec), "hugmesh", true,
                Map.of("brandx", "orgx", "brandy", "orgy"));
        StepVerifier.create(c.belongsToDomain("victim", "brandx"))
                .expectNext(false).verifyComplete();
        // The probe used brandX's org (orgx/victim), proving the read is caller-scoped.
        assertThat(rec.requests.get(0).url().getQuery()).contains("orgx").contains("victim");
    }

    // ── belongsToDomain fails CLOSED when the seam is disabled (dev/CI) ──
    @Test
    void belongsToDomain_seamDisabled_isFalse_noHttp() {
        Recorder rec = new Recorder(Map.of());
        CasdoorRoleClient c = new CasdoorRoleClient(web(rec), "hugmesh", false, Map.of());
        StepVerifier.create(c.belongsToDomain("alice", "brandx"))
                .expectNext(false).verifyComplete();
        assertThat(rec.requests).isEmpty();   // no Casdoor round-trip when disabled
    }

    // ── BUG-C: isPrivileged FAILS CLOSED on a Casdoor outage (enabled seam) ────
    // Previously membersOf swallowed the error to an empty list → isPrivileged=false →
    // a MOD could ban an ADMIN/MOD when the role lookup errored (failed OPEN), asymmetric
    // with belongsToDomain (which fails closed). The fix resolves privileged=TRUE on an
    // error so the ban is DENIED. FAIL-FIRST: against the unfixed swallow this expects
    // false (allow), so the new assertion (true) would fail.
    @Test
    void isPrivileged_casdoorError_failsClosed_resolvesTrue() {
        // The role-read endpoint errors (e.g. a 5xx / connection failure). Enabled seam.
        ExchangeFunction erroring = request ->
                Mono.error(new RuntimeException("casdoor unreachable"));
        CasdoorRoleClient c = new CasdoorRoleClient(
                WebClient.builder().baseUrl("http://casdoor.test").exchangeFunction(erroring).build(),
                "hugmesh", true, Map.of("brandx", "orgx"));
        StepVerifier.create(c.isPrivileged("anadmin", "brandx"))
                // fail CLOSED: an unresolvable target is treated as PRIVILEGED → ban denied.
                .expectNext(true).verifyComplete();
    }

    // ── finding-6 FIX: disabled seam + BRANDED caller FAILS CLOSED (privileged=true) ──
    // The privileged-target guard is the ONLY control stopping a MOD banning an ADMIN/MOD.
    // With the seam OFF (the default casdoor.admin.enabled=false) a BRANDED — i.e.
    // multi-tenant / production — caller's target roles are unprovable, so the target is
    // treated as PRIVILEGED and the ban/block/domain-lock is DENIED, mirroring
    // belongsToDomain's fail-closed contract. FAIL-FIRST: against the old fail-OPEN
    // disabled-seam branch this expected false (allow) → the new assertion (true) fails.
    @Test
    void isPrivileged_seamDisabled_brandedCaller_failsClosed_resolvesTrue() {
        Recorder rec = new Recorder(Map.of());
        CasdoorRoleClient c = new CasdoorRoleClient(web(rec), "hugmesh", false, Map.of());
        StepVerifier.create(c.isPrivileged("anadmin", "brandx"))
                // branded caller, unprovable membership → PRIVILEGED → ban denied.
                .expectNext(true).verifyComplete();
        assertThat(rec.requests).isEmpty();   // disabled seam never reaches Casdoor
    }

    // ── finding-6 control: disabled seam + SINGLE-TENANT caller keeps permissive default ──
    // A null/blank/'default' caller domain is the legacy single-org / dev / CI flow: one
    // Casdoor org, no cross-tenant surface. The disabled-seam guard stays permissive
    // (privileged=false) so ordinary moderation keeps working offline exactly as before —
    // the always-on self-ban + method/gateway gates remain the live controls there.
    @Test
    void isPrivileged_seamDisabled_singleTenantCaller_isFalse_noHttp() {
        Recorder rec = new Recorder(Map.of());
        CasdoorRoleClient c = new CasdoorRoleClient(web(rec), "hugmesh", false, Map.of());
        StepVerifier.create(c.isPrivileged("anadmin", null))
                .expectNext(false).verifyComplete();
        StepVerifier.create(c.isPrivileged("anadmin", "default"))
                .expectNext(false).verifyComplete();
        // The legacy single-arg form is single-tenant (null domain) → permissive too.
        StepVerifier.create(c.isPrivileged("anadmin"))
                .expectNext(false).verifyComplete();
        assertThat(rec.requests).isEmpty();   // disabled seam never reaches Casdoor
    }

    // ── isPrivileged keys the role read off the CALLER's brand org (CROSS-USER) ──
    @Test
    void isPrivileged_keysRoleReadOffCallersOrg() {
        // brand-X admin membership lives in orgx; the target 'someadmin' is in it.
        Recorder rec = new Recorder(Map.of(
                "orgx/ROLE_ADMIN", "{\"data\":{\"users\":[\"orgx/someadmin\"]}}",
                "orgx/ROLE_MOD", "{\"data\":{\"users\":[]}}"));
        CasdoorRoleClient c = new CasdoorRoleClient(web(rec), "hugmesh", true,
                Map.of("brandx", "orgx"));
        StepVerifier.create(c.isPrivileged("someadmin", "brandx"))
                .expectNext(true).verifyComplete();
        // Both role reads were against brandX's org (orgx), never the static 'hugmesh'.
        assertThat(rec.requests).allSatisfy(r ->
                assertThat(r.url().getQuery()).contains("orgx"));
    }
}
