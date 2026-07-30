package systems.hugmesh.modbff.auth;

import org.springframework.http.HttpHeaders;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * The INTERNAL service-to-service client mod-bff-api uses to bridge an opaque
 * {@code bff_} session token into admin-bff-api's account/role truth, over the SAME
 * {@code /bff/internal/session/introspect} endpoint the gateway's own
 * {@code BffSessionAuthFilter} calls for its route-access decision.
 *
 * <p>mod-bff-api has NO local database access to the accounts/bff_session tables
 * (network-isolated from admin-bff-db by design — see the platform NetworkPolicy),
 * so unlike admin-bff-api's OWN {@code BffCookieAuthenticationWebFilter} (which
 * resolves a session via a direct, in-process {@code AccountStore} call), this
 * service must resolve over HTTP. One call suffices: admin-bff's introspect
 * response already carries {@code id}/{@code roles}/{@code registrationComplete}/
 * {@code status}/{@code mfaSatisfied} — everything {@link BffCookieAuthenticationWebFilter}'s
 * authority mapping needs — so there is no second "fetch the full account" hop the
 * way {@code user-bff-api}'s older {@code AdminBffInternalClient.getAccountBySession}
 * needs (that client ALSO needs {@code handle}, which introspect omits; this one does
 * not).
 *
 * <p>Talks to a DEDICATED WebClient ({@link AdminBffSessionAuthConfig}) that stamps
 * {@code X-Internal-Token} and optionally presents this BFF's mTLS client identity —
 * separate from {@code AdminApiConfig}'s existing {@code adminBffWebClient}, which
 * forwards the CALLER's bearer against admin-bff's PUBLIC surface and carries no
 * internal-token credential for the {@code /bff/internal/**} surface's
 * {@code InternalTokenWebFilter} guard.
 *
 * <p>No fail-closed-stub null check here (unlike {@code user-bff-api}'s
 * {@code AdminBffInternalClient}): this client is only ever constructed with a real,
 * non-null {@link WebClient} (see {@link AdminBffSessionAuthConfig}); the "is a client
 * even wired" question is instead answered by the WEBFILTER via
 * {@code ObjectProvider<AdminBffSessionIntrospectClient>}, exactly like admin-bff-api's
 * own {@code ObjectProvider<AccountStore>} — so a slice-test context that never wires
 * this config degrades to pass-through-unauthenticated rather than failing to
 * construct.
 */
public class AdminBffSessionIntrospectClient {

    private final WebClient http;

    public AdminBffSessionIntrospectClient(WebClient http) {
        this.http = http;
    }

    /**
     * Resolve an opaque {@code bff_} token against admin-bff. Unknown/expired session
     * -&gt; the admin-bff 401 propagates as a {@code WebClientResponseException.Unauthorized}
     * (the caller maps that to "pass through unauthenticated"); any other failure
     * (network error, timeout, 5xx) propagates as-is (the caller fails closed).
     */
    public Mono<BffSessionIntrospection> introspect(String bffToken) {
        return http.get()
                .uri("/bff/internal/session/introspect")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + bffToken)
                .retrieve()
                .bodyToMono(BffSessionIntrospection.class);
    }
}
