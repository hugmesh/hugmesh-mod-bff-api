package net.hugmesh.modbff.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The step-up predicate itself — the two flag states and the fail-closed edges,
 * without any Spring context. The wiring into {@code @PreAuthorize} is covered by
 * {@code ModStepUpGateControllerTest}.
 */
class ModStepUpGateTest {

    private static Authentication auth(String... authorities) {
        List<GrantedAuthority> granted = new ArrayList<>();
        for (String a : authorities) granted.add(new SimpleGrantedAuthority(a));
        return new UsernamePasswordAuthenticationToken("mod:bob", null, granted);
    }

    // ── DARK default: the gate is inert ───────────────────────────────────────
    @Test
    void darkGate_allowsEvenWithoutMfaMarker() {
        ModStepUpGate gate = new ModStepUpGate(false);
        assertThat(gate.isEnforced()).isFalse();
        assertThat(gate.satisfied(auth("ROLE_MOD"))).isTrue();
    }

    /** Dark means dark: even a null principal is not the gate's business to deny —
     *  the role gate and the chain's {@code authenticated()} rule already ran. */
    @Test
    void darkGate_allowsNullAuthentication() {
        assertThat(new ModStepUpGate(false).satisfied(null)).isTrue();
    }

    // ── ARMED: only a proved second factor passes ─────────────────────────────
    @Test
    void armedGate_deniesWithoutMfaMarker() {
        ModStepUpGate gate = new ModStepUpGate(true);
        assertThat(gate.isEnforced()).isTrue();
        assertThat(gate.satisfied(auth("ROLE_USER", "ROLE_MOD", "DOMAIN_default"))).isFalse();
    }

    @Test
    void armedGate_allowsWithMfaMarker() {
        assertThat(new ModStepUpGate(true)
                .satisfied(auth("ROLE_MOD", Roles.MFA_SATISFIED))).isTrue();
    }

    /** Fail-closed: no authentication cannot prove a second factor. */
    @Test
    void armedGate_deniesNullAuthentication() {
        assertThat(new ModStepUpGate(true).satisfied(null)).isFalse();
    }

    /** The marker is EXACT — a look-alike authority does not satisfy the gate. */
    @Test
    void armedGate_deniesLookAlikeAuthority() {
        assertThat(new ModStepUpGate(true)
                .satisfied(auth("ROLE_MFA_SATISFIED", "MFA_SATISFIED_AT"))).isFalse();
    }
}
