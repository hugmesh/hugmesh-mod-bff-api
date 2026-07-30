package systems.hugmesh.modbff.federation;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit coverage for the federation manifest DTO's encapsulation contract.
 *
 * <p>federation-api visibility/role-filters the manifest server-side and the BFF passes it
 * through unfiltered, so the remotes list this DTO carries is already-authorised content.
 * It must not be mutable after construction — an aliased list would let a caller graft an
 * unauthorised remote onto a manifest that had already cleared federation-api's filter.
 */
class FederationManifestDtoTest {

    private static FederationManifestDto.FederationRemoteDto remote(String slug) {
        return new FederationManifestDto.FederationRemoteDto(
                slug, slug, "mod", "https://example.test/remoteEntry.json",
                "./Module", "1.0.0", "sha256-x", "mod", "{}");
    }

    // ── ENCAPSULATION (EI_EXPOSE_REP2): the record must not alias the caller's list ────
    @Test
    void constructorDefensivelyCopies_callerCannotAddRemotesAfterConstruction() {
        List<FederationManifestDto.FederationRemoteDto> caller =
                new ArrayList<>(List.of(remote("authorised")));
        FederationManifestDto manifest = new FederationManifestDto("2026-07-17T00:00:00Z", caller);

        caller.add(remote("unauthorised")); // post-construction injection via the aliased list

        assertThat(manifest.remotes()).extracting(FederationManifestDto.FederationRemoteDto::slug)
                .containsExactly("authorised");
    }

    // ── ENCAPSULATION (EI_EXPOSE_REP): the accessor must not hand back a mutable list ──
    // Mutable ArrayList input on purpose — an immutable List.of(...) would make this
    // assertion vacuous (it would hold even with no defensive copy at all).
    @Test
    void accessorReturnsImmutableList_callerCannotMutateInternals() {
        FederationManifestDto manifest = new FederationManifestDto(
                "2026-07-17T00:00:00Z", new ArrayList<>(List.of(remote("authorised"))));

        assertThatThrownBy(() -> manifest.remotes().add(remote("unauthorised")))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(manifest.remotes()).hasSize(1);
    }

    // A null remotes list stays an empty list (the previous accessor's contract).
    @Test
    void nullRemotesList_collapsesToEmpty() {
        assertThat(new FederationManifestDto("2026-07-17T00:00:00Z", null).remotes()).isEmpty();
    }
}
