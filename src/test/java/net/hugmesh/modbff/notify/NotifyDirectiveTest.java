package net.hugmesh.modbff.notify;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit coverage for the SERVICE-SCOPED {@code @system} notification directive resolver
 * (Notifications PR6).
 *
 * <ul>
 *   <li>in-app + email are always allowed regardless of the action's platform;</li>
 *   <li>a platform-bound channel (matrix/mastodon) is allowed ONLY when it matches the
 *       action's platform — an off-scope channel is DROPPED;</li>
 *   <li>notify_email_only FORCES exactly email+in-app, overriding the channel list;</li>
 *   <li>the directive carries NO actor — there is no field or constructor for it.</li>
 * </ul>
 */
class NotifyDirectiveTest {

    // ── ENCAPSULATION: a resolved, service-scoped channel set must not be widenable ────
    // after the fact by mutating the list that was handed to the constructor. This is the
    // security-relevant half of the EI_EXPOSE_REP2 fix: without the constructor's
    // defensive copy the directive aliases the caller's list, so a caller that retains a
    // reference could add an off-scope channel (e.g. "mastodon" onto a matrix action)
    // AFTER resolve() already scoped it — bypassing the scoping rules entirely.
    @Test
    void constructorDefensivelyCopies_callerCannotWidenScopeAfterConstruction() {
        List<String> caller = new ArrayList<>(List.of("in-app"));
        NotifyDirective directive = new NotifyDirective(caller, false);

        caller.add("mastodon"); // the caller mutates the list it passed in, post-construction

        assertThat(directive.channels()).containsExactly("in-app");
        assertThat(directive.toCsv()).isEqualTo("in-app");
    }

    // The accessor must likewise never hand back a mutable internal list (EI_EXPOSE_REP).
    // Constructed from a mutable ArrayList on purpose — resolve()/List.of() inputs would
    // make this assertion vacuous, since the internal list would already be immutable.
    @Test
    void accessorReturnsImmutableList_callerCannotMutateInternals() {
        NotifyDirective directive = new NotifyDirective(new ArrayList<>(List.of("in-app")), false);

        assertThatThrownBy(() -> directive.channels().add("mastodon"))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThat(directive.channels()).containsExactly("in-app");
    }

    // ── SERVICE-SCOPING: a matrix ban may notify matrix; a mastodon channel is dropped ─
    @Test
    void platformBoundChannel_onlyHonouredWhenItMatchesThePlatform() {
        NotifyDirective onScope = NotifyDirective.resolve("matrix", List.of("in-app", "matrix"), false);
        assertThat(onScope.channels()).containsExactly("in-app", "matrix");

        // A matrix ban requesting the mastodon channel: mastodon is OFF-SCOPE → dropped.
        NotifyDirective offScope = NotifyDirective.resolve("matrix", List.of("in-app", "mastodon"), false);
        assertThat(offScope.channels()).containsExactly("in-app");
        assertThat(offScope.channels()).doesNotContain("mastodon");
    }

    // ── in-app + email are always allowed; unknown channels dropped ──────────
    @Test
    void inAppAndEmail_alwaysAllowed_unknownDropped() {
        NotifyDirective d = NotifyDirective.resolve("profile",
                List.of("in-app", "email", "matrix", "carrier-pigeon"), false);
        // profile is not a platform-bound channel, so matrix is off-scope here too.
        assertThat(d.channels()).containsExactly("in-app", "email");
    }

    // ── email-only FORCES email+in-app, overriding the requested list ────────
    @Test
    void emailOnly_forcesEmailAndInApp_overridingTheList() {
        NotifyDirective d = NotifyDirective.resolve("matrix", List.of("matrix", "in-app"), true);
        assertThat(d.channels()).containsExactlyInAnyOrder("in-app", "email");
        assertThat(d.emailOnly()).isTrue();
        assertThat(d.channels()).doesNotContain("matrix");
    }

    // ── empty / null requests → no directive ─────────────────────────────────
    @Test
    void emptyOrNull_isNoDirective() {
        assertThat(NotifyDirective.resolve("matrix", null, false).any()).isFalse();
        assertThat(NotifyDirective.resolve("matrix", List.of(), false).any()).isFalse();
        assertThat(NotifyDirective.none().toCsv()).isNull();
    }

    // ── CSV form + dedup/order-stability ─────────────────────────────────────
    @Test
    void toCsv_isOrderStableAndDeduped() {
        NotifyDirective d = NotifyDirective.resolve("mastodon",
                List.of("in-app", "mastodon", "in-app", "MASTODON"), false);
        assertThat(d.toCsv()).isEqualTo("in-app,mastodon");
    }
}
