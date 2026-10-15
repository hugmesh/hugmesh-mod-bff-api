package net.hugmesh.modbff.service;

import net.hugmesh.modbff.admin.AdminDomainLockClient;
import net.hugmesh.modbff.admin.AdminSuspensionClient;
import net.hugmesh.modbff.admin.CasdoorRoleClient;
import net.hugmesh.modbff.audit.ModAction;
import net.hugmesh.modbff.audit.ModActionRepository;
import net.hugmesh.modbff.external.MastodonAdminClient;
import net.hugmesh.modbff.external.MatrixAdminClient;
import net.hugmesh.modbff.owncast.OwncastModClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Wire-level contract for hugmesh-mod-bff-api#26. {@code ModService} is driven with the
 * REAL {@link AdminDomainLockClient} (only the HTTP exchange is recorded), so the test
 * sees the request URL admin-bff would receive. Every other test stubs the client, which
 * is how the {@code /domain-lock/matrix/<user>} 400 shipped: each side passed against its
 * own mock of the other. admin-bff maps {@code /bff/admin/domain-lock/{role}/{user}} with
 * {@code @Pattern(ROLE_MATRIX_DOMAINLOCKED|ROLE_MASTODON_DOMAINLOCKED)}, so that is the
 * exact path pinned here for the reversible Matrix user block (decision 51) and for the
 * plain domain-lock / unlock endpoints.
 */
class DomainLockWireContractTest {

    static class Recorder implements ExchangeFunction {
        final List<ClientRequest> requests = new ArrayList<>();

        @Override
        public Mono<ClientResponse> exchange(ClientRequest request) {
            requests.add(request);
            return Mono.just(ClientResponse.create(HttpStatus.OK).body("").build());
        }
    }

    Recorder wire;
    CasdoorRoleClient roles;
    ModActionRepository audit;
    ModService service;

    private static Authentication mod() {
        return new UsernamePasswordAuthenticationToken("mod:bob", "n/a",
                AuthorityUtils.createAuthorityList("ROLE_MOD", "ROLE_MATRIX", "ROLE_MASTODON", "DOMAIN_default"));
    }

    @BeforeEach
    void setUp() {
        wire = new Recorder();
        WebClient web = WebClient.builder().baseUrl("http://admin-bff.test").exchangeFunction(wire).build();
        roles = mock(CasdoorRoleClient.class);
        audit = mock(ModActionRepository.class);
        service = new ModService(mock(AdminSuspensionClient.class), new AdminDomainLockClient(web), roles, audit,
                mock(MatrixAdminClient.class), mock(MastodonAdminClient.class), mock(OwncastModClient.class));
        when(roles.isPrivileged(anyString(), any())).thenReturn(Mono.just(false));
        when(roles.belongsToDomain(anyString(), any())).thenReturn(Mono.just(true));
        ModAction row = new ModAction("id-1", "mod:bob", "domain.lock", "access", "alice", null, "pending",
                LocalDateTime.parse("2026-06-06T00:00:00"), "k", "user", null, "pending");
        when(audit.recordBan(anyString(), anyString(), anyString(), anyString(), anyString(),
                any(), any(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(new ModActionRepository.RecordedBan(row, true)));
        when(audit.record(anyString(), anyString(), anyString(), anyString(), any(), anyString(), anyString()))
                .thenReturn(Mono.just(row));
    }

    @Test
    void matrixUserBlock_postsTheMatrixDomainLockRole() {
        StepVerifier.create(service.block("matrix", "user", "alice", "abuse", mod()))
                .expectNextCount(1).verifyComplete();
        assertThat(wire.requests).hasSize(1);
        assertThat(wire.requests.get(0).method()).isEqualTo(HttpMethod.POST);
        assertThat(wire.requests.get(0).url().getRawPath())
                .isEqualTo("/bff/admin/domain-lock/ROLE_MATRIX_DOMAINLOCKED/alice");
    }

    @Test
    void domainLock_postsTheRoleItWasGiven() {
        StepVerifier.create(service.domainLock("ROLE_MASTODON_DOMAINLOCKED", "alice", "abuse", null, mod()))
                .expectNextCount(1).verifyComplete();
        assertThat(wire.requests).hasSize(1);
        assertThat(wire.requests.get(0).method()).isEqualTo(HttpMethod.POST);
        assertThat(wire.requests.get(0).url().getRawPath())
                .isEqualTo("/bff/admin/domain-lock/ROLE_MASTODON_DOMAINLOCKED/alice");
    }

    @Test
    void domainUnlock_deletesTheRoleItWasGiven_soBlockThenUnlockIsOneRoundTrip() {
        StepVerifier.create(service.block("matrix", "user", "alice", "abuse", mod()))
                .expectNextCount(1).verifyComplete();
        StepVerifier.create(service.domainUnlock("ROLE_MATRIX_DOMAINLOCKED", "alice", null, mod()))
                .expectNextCount(1).verifyComplete();
        assertThat(wire.requests).hasSize(2);
        assertThat(wire.requests.get(1).method()).isEqualTo(HttpMethod.DELETE);
        assertThat(wire.requests.get(1).url().getRawPath())
                .isEqualTo(wire.requests.get(0).url().getRawPath());
    }
}
