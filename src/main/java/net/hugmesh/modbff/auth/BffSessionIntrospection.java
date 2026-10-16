package net.hugmesh.modbff.auth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;
import java.util.Objects;

/**
 * Projection of admin-bff-api's {@code GET /bff/internal/session/introspect} response
 * body ({@code net.hugmesh.adminbff.internalapi.InternalAccountController.IntrospectResponse}),
 * which in turn mirrors the gateway's own {@code BffSessionAuthFilter.MeResponse} — all
 * three shapes are kept field-for-field identical by convention so any of them can
 * deserialize the same wire body without a shared module dependency.
 *
 * <p>{@code @JsonIgnoreProperties(ignoreUnknown = true)}: only the fields this filter's
 * authority mapping needs are declared, so admin-bff can add response fields later
 * without breaking this client.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record BffSessionIntrospection(
        String id,
        String provider,
        List<String> roles,
        boolean registrationComplete,
        String status,
        boolean mfaSatisfied) {

    /** Compact constructor: safe defaults for optional fields — a partial body never NPEs the
     *  mapping. A missing {@code status} becomes blank (unknown), which {@code
     *  BffCookieAuthenticationWebFilter} refuses (403); it is never defaulted to "active".
     *
     *  <p>{@code roles} is additionally defensively copied into an immutable list, so this
     *  record neither aliases a list the caller can still mutate nor hands one back from
     *  the accessor — the deserialized authority source must not be rewritable after
     *  introspection.
     *
     *  <p>Null ELEMENTS are dropped rather than copied verbatim. {@link List#copyOf}
     *  rejects them outright, and a null role is a tolerated wire value here, so copying
     *  verbatim is not an option and rejecting would turn a body admin-bff may
     *  legitimately send ({@code {"roles":[null]}}) into a deserialization NPE. Dropping
     *  is observably equivalent for the only consumer:
     *  {@code BffCookieAuthenticationWebFilter.buildAuthorities} already skips any
     *  {@code role == null}.
     *
     *  <p>The outer {@link List#copyOf} around the already-immutable {@code toList()}
     *  result is LOAD-BEARING, not redundant — do not "simplify" it away. It costs
     *  nothing at runtime ({@code copyOf} returns an {@code ImmutableCollections} list
     *  as-is rather than re-copying), but {@code copyOf} is the specific marker
     *  SpotBugs' EI_EXPOSE_REP analysis recognises as making the field safe to return
     *  from the accessor. Verified empirically against spotbugs 4.9.8.2 on this class:
     *  {@code Collections.unmodifiableList(new ArrayList<>(roles))} and a bare
     *  {@code .stream()...toList()} BOTH still reported EI_EXPOSE_REP; wrapping in
     *  {@code List.copyOf} is what cleared it. */
    public BffSessionIntrospection {
        if (id == null) id = "";
        if (provider == null) provider = "";
        roles = roles == null ? List.of() : List.copyOf(roles.stream().filter(Objects::nonNull).toList());
        // NOT defaulted to "active": a body that omits status must not read as a live account.
        // Blank is the "unknown" value the filter's allow-list refuses.
        if (status == null) status = "";
    }
}
