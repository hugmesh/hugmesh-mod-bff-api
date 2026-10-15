package net.hugmesh.modbff.tube;

import reactor.core.publisher.Mono;
import net.hugmesh.modbff.external.BlockOutcome;

/**
 * The effector seam for tube moderation. hugmesh-tube-bff-api exposes no moderation
 * endpoint yet, so this repo ships only the interface: no HTTP implementation and no
 * bean. {@code ModService.tubeHide} refuses to run (and writes no ledger row) until an
 * implementation is registered.
 *
 * <p>An implementation follows the {@code OwncastModClient} contract: a success is a
 * SYNCHRONOUSLY applied effect ({@link BlockOutcome#OK}), a real "no such content"
 * answer propagates as an error, and any other failure resolves to
 * {@link BlockOutcome#degraded(String)} so the ledger records the honest outcome.
 */
public interface TubeModClient {

    /** HIDE the target owner's tube content. */
    Mono<BlockOutcome> hide(String ownerSubject, String reason);
}
