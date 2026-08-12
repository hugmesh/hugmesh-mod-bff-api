package net.hugmesh.modbff.federation;

import reactor.core.publisher.Mono;

/**
 * The transport seam {@link SessionExchangeService} depends on, rather than concretely on
 * {@link SessionExchangeClient} — lets tests exercise {@link SessionExchangeService}'s
 * caching/error-categorisation logic with a plain lambda instead of a fake {@code
 * WebClient}/{@code ExchangeFunction}. {@link SessionExchangeClient} is the sole production
 * implementation.
 */
@FunctionalInterface
interface SessionExchangeTransport {
    Mono<String> exchange(String rawToken);
}
