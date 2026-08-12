package net.hugmesh.modbff.federation;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Wire shape returned by federation-api {@code GET /api/federation/manifest},
 * matched field-for-field to federation-api
 * {@code net.hugmesh.federation.model.FederationManifestDto}:
 * {@code {generatedAt, remotes[]}} where each remote is
 * {@code {slug, displayName, kind, remoteEntryUrl, exposedModule, version,
 * contentHash, visibility, metadata}}.
 *
 * <p>The BFF passes this through to the mod-ui host so native-federation's
 * {@code initFederation(...)} can register the MOD-accessible remotes.
 * federation-api already visibility/role-filters the manifest server-side against
 * the forwarded JWT's authorities, so the BFF does NOT re-filter.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record FederationManifestDto(
        String generatedAt,
        List<FederationRemoteDto> remotes
) {
    /** Compact constructor: {@code remotes} is defensively copied into an immutable list
     *  ONCE at construction, so the record neither aliases the caller's list (which the
     *  caller could mutate afterwards) nor re-copies on every accessor call. The accessor
     *  is therefore the record's default one — it returns an already-immutable field.
     *  Null collapses to an empty list, preserving the previous accessor's contract. */
    public FederationManifestDto {
        remotes = remotes == null ? List.of() : List.copyOf(remotes);
    }
    @JsonIgnoreProperties(ignoreUnknown = true)
    public record FederationRemoteDto(
            String slug,
            String displayName,
            String kind,
            String remoteEntryUrl,
            String exposedModule,
            String version,
            String contentHash,
            String visibility,
            String metadata
    ) {}
}
