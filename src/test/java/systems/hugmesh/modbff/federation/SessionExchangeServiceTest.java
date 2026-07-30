package systems.hugmesh.modbff.federation;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link SessionExchangeService} NEVER errors — every failure mode (the exchange
 * endpoint's own documented fail-closed matrix, and any transient/unexpected failure)
 * collapses to {@link Mono#empty()}, and only a SUCCESSFUL exchange is cached.
 */
class SessionExchangeServiceTest {

    private static WebClientResponseException statusException(int status) {
        return WebClientResponseException.create(status, "test", null, null, null);
    }

    @Test
    void successfulExchange_emitsTheBearer() {
        SessionExchangeService svc = new SessionExchangeService(
                rawToken -> Mono.just("real-jwt"), new SessionExchangeCache(5000, 10), Duration.ofSeconds(1));

        StepVerifier.create(svc.exchange("bff_abc")).expectNext("real-jwt").verifyComplete();
    }

    @Test
    void blankToken_neverCallsTransport_completesEmpty() {
        AtomicInteger calls = new AtomicInteger();
        SessionExchangeService svc = new SessionExchangeService(
                rawToken -> { calls.incrementAndGet(); return Mono.just("real-jwt"); },
                new SessionExchangeCache(5000, 10), Duration.ofSeconds(1));

        StepVerifier.create(svc.exchange("")).verifyComplete();
        StepVerifier.create(svc.exchange(null)).verifyComplete();
        assertThat(calls.get()).isZero();
    }

    @Test
    void routineFailure_503CustodyDisabled_degradesToEmpty_notAnError() {
        SessionExchangeService svc = new SessionExchangeService(
                rawToken -> Mono.error(statusException(503)),
                new SessionExchangeCache(5000, 10), Duration.ofSeconds(1));

        StepVerifier.create(svc.exchange("bff_abc")).verifyComplete();
    }

    @Test
    void routineFailure_404UnknownSession_degradesToEmpty() {
        SessionExchangeService svc = new SessionExchangeService(
                rawToken -> Mono.error(statusException(404)),
                new SessionExchangeCache(5000, 10), Duration.ofSeconds(1));

        StepVerifier.create(svc.exchange("bff_abc")).verifyComplete();
    }

    @Test
    void routineFailure_401NoCustody_degradesToEmpty() {
        SessionExchangeService svc = new SessionExchangeService(
                rawToken -> Mono.error(statusException(401)),
                new SessionExchangeCache(5000, 10), Duration.ofSeconds(1));

        StepVerifier.create(svc.exchange("bff_abc")).verifyComplete();
    }

    @Test
    void routineFailure_403Suspended_degradesToEmpty() {
        SessionExchangeService svc = new SessionExchangeService(
                rawToken -> Mono.error(statusException(403)),
                new SessionExchangeCache(5000, 10), Duration.ofSeconds(1));

        StepVerifier.create(svc.exchange("bff_abc")).verifyComplete();
    }

    @Test
    void unexpectedFailure_500_stillDegradesToEmpty_notAnError() {
        SessionExchangeService svc = new SessionExchangeService(
                rawToken -> Mono.error(statusException(500)),
                new SessionExchangeCache(5000, 10), Duration.ofSeconds(1));

        StepVerifier.create(svc.exchange("bff_abc")).verifyComplete();
    }

    @Test
    void connectionRefused_degradesToEmpty_notAnError() {
        SessionExchangeService svc = new SessionExchangeService(
                rawToken -> Mono.error(new java.net.ConnectException("refused")),
                new SessionExchangeCache(5000, 10), Duration.ofSeconds(1));

        StepVerifier.create(svc.exchange("bff_abc")).verifyComplete();
    }

    @Test
    void transportTimeout_degradesToEmpty_notAnError() {
        SessionExchangeService svc = new SessionExchangeService(
                rawToken -> Mono.never(), // never completes -> service-level timeout fires
                new SessionExchangeCache(5000, 10), Duration.ofMillis(20));

        StepVerifier.create(svc.exchange("bff_abc")).verifyComplete();
    }

    @Test
    void successfulExchange_isCached_transportCalledOnlyOnce() {
        AtomicInteger calls = new AtomicInteger();
        SessionExchangeService svc = new SessionExchangeService(
                rawToken -> { calls.incrementAndGet(); return Mono.just("real-jwt"); },
                new SessionExchangeCache(5000, 10), Duration.ofSeconds(1));

        StepVerifier.create(svc.exchange("bff_abc")).expectNext("real-jwt").verifyComplete();
        StepVerifier.create(svc.exchange("bff_abc")).expectNext("real-jwt").verifyComplete();
        assertThat(calls.get()).isEqualTo(1);
    }

    @Test
    void failedExchange_isNeverCached_transportCalledEveryTime() {
        AtomicInteger calls = new AtomicInteger();
        SessionExchangeService svc = new SessionExchangeService(
                rawToken -> { calls.incrementAndGet(); return Mono.error(statusException(503)); },
                new SessionExchangeCache(5000, 10), Duration.ofSeconds(1));

        StepVerifier.create(svc.exchange("bff_abc")).verifyComplete();
        StepVerifier.create(svc.exchange("bff_abc")).verifyComplete();
        assertThat(calls.get()).isEqualTo(2);
    }

    @Test
    void cacheDisabled_everyCallHitsTransport() {
        AtomicInteger calls = new AtomicInteger();
        SessionExchangeService svc = new SessionExchangeService(
                rawToken -> { calls.incrementAndGet(); return Mono.just("real-jwt"); },
                new SessionExchangeCache(0, 10), Duration.ofSeconds(1));

        StepVerifier.create(svc.exchange("bff_abc")).expectNext("real-jwt").verifyComplete();
        StepVerifier.create(svc.exchange("bff_abc")).expectNext("real-jwt").verifyComplete();
        assertThat(calls.get()).isEqualTo(2);
    }

    @Test
    void blankBearerInResponse_isTreatedAsAFailure_notCached() {
        // Mirrors SessionExchangeClient#exchange's own "blank bearer -> Mono.empty()"
        // contract for an otherwise-2xx response.
        AtomicInteger calls = new AtomicInteger();
        SessionExchangeService svc = new SessionExchangeService(
                rawToken -> { calls.incrementAndGet(); return Mono.empty(); },
                new SessionExchangeCache(5000, 10), Duration.ofSeconds(1));

        StepVerifier.create(svc.exchange("bff_abc")).verifyComplete();
        StepVerifier.create(svc.exchange("bff_abc")).verifyComplete();
        assertThat(calls.get()).isEqualTo(2);
    }
}
