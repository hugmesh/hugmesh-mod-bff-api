package systems.hugmesh.modbff.auth;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit coverage for the introspection projection's encapsulation + null-tolerance
 * contract.
 *
 * <p>{@code roles} is this BFF's authority source: {@code BffCookieAuthenticationWebFilter
 * .buildAuthorities} maps it straight to {@code ROLE_*} grants. It therefore must not be
 * rewritable after introspection, and must not blow up on the null elements the wire body
 * is already written to tolerate.
 */
class BffSessionIntrospectionTest {

    private static BffSessionIntrospection withRoles(List<String> roles) {
        return new BffSessionIntrospection("casdoor:mod1", "casdoor", roles, true, "active", false);
    }

    // ── ENCAPSULATION (EI_EXPOSE_REP2): the record must not alias the caller's list ────
    @Test
    void constructorDefensivelyCopies_callerCannotGrantItselfRolesAfterConstruction() {
        List<String> caller = new ArrayList<>(List.of("mod"));
        BffSessionIntrospection intro = withRoles(caller);

        caller.add("superadmin"); // post-construction escalation attempt via the aliased list

        assertThat(intro.roles()).containsExactly("mod");
    }

    // ── ENCAPSULATION (EI_EXPOSE_REP): the accessor must not hand back a mutable list ──
    // The input list is deliberately a MUTABLE ArrayList: handing in an already-immutable
    // List.of(...) would make this assertion vacuous (it would hold with or without the
    // defensive copy, since the record would just be returning the immutable list it was
    // given). Only a mutable input actually exercises the copy.
    @Test
    void accessorReturnsImmutableList_callerCannotMutateInternals() {
        BffSessionIntrospection intro = withRoles(new ArrayList<>(List.of("mod")));

        assertThatThrownBy(() -> intro.roles().add("superadmin"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(intro.roles()).containsExactly("mod");
    }

    // ── NULL-TOLERANCE: the defensive copy must not regress the tolerated wire body ────
    // buildAuthorities already skips `role == null`, so a {"roles":[null]} body is
    // harmless today. The copy drops null elements rather than rejecting them, so this
    // must NOT become a deserialization NPE (List.copyOf(roles) verbatim would throw).
    @Test
    void nullRoleElements_areDroppedNotRejected() {
        List<String> withNulls = Arrays.asList("mod", null, "auditor");

        assertThatCode(() -> withRoles(withNulls)).doesNotThrowAnyException();
        assertThat(withRoles(withNulls).roles()).containsExactly("mod", "auditor");
        assertThat(withRoles(Arrays.asList((String) null)).roles()).isEmpty();
    }

    // A null roles list stays an empty list (pre-existing compact-constructor contract).
    @Test
    void nullRolesList_collapsesToEmpty() {
        assertThat(withRoles(null).roles()).isEmpty();
    }
}
