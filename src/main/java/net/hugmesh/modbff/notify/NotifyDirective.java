package net.hugmesh.modbff.notify;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * The SERVICE-SCOPED {@code @system} notification directive a moderator attaches to a
 * ban / lift / lock (Notifications PR6): WHICH channels to notify the affected user on,
 * resolved relative to the action's platform.
 *
 * <h3>Identity rule (load-bearing)</h3>
 * This type describes the requested FAN-OUT only. It carries NO actor — there is no
 * field for, and no path that records, the acting mod's identity. The neutral
 * {@code @system} sender (whose outbox row is built in admin-bff) copies the reason/ttl
 * but NEVER {@code mod_action.actor}, so a notified user can never see who moderated them
 * (the same posture as the public {@code AppealContact} resolver). The dedicated
 * no-mod-identity test asserts the persisted directive + the forwarded request carry no
 * actor token.
 *
 * <h3>Service-scoping</h3>
 * {@link #resolve(String, List, boolean)} normalises a raw request against the action's
 * {@code platform}:
 * <ul>
 *   <li>{@code in-app} is ALWAYS allowed (the floor — it is the user's own console, not a
 *       federated service the action's platform must own);</li>
 *   <li>a platform-bound channel ({@code matrix} / {@code mastodon}) is allowed ONLY when
 *       the action's platform matches it (a {@code matrix} ban may notify {@code matrix};
 *       it may NOT spray a {@code mastodon} DM) — anything off-scope is DROPPED;</li>
 *   <li>{@code email} is always allowed (a cross-service, address-based channel);</li>
 *   <li>{@code notifyEmailOnly=true} FORCES the directive to exactly {@code email} +
 *       {@code in-app} (the conservative low-noise option), overriding the channel list.</li>
 * </ul>
 * The result is a deduped, order-stable channel set; an empty set means "no external
 * notification requested" (the in-app floor still applies on its own path).
 */
public record NotifyDirective(List<String> channels, boolean emailOnly) {

    /** Compact constructor: {@code channels} is defensively copied into an immutable list
     *  ONCE at construction, so the directive neither aliases the caller's list (a resolved,
     *  service-scoped channel set must not be widenable after the fact by mutating the list
     *  that was passed in) nor re-copies on every accessor call. The accessor is therefore
     *  the record's default one — it returns an already-immutable field. Null collapses to
     *  an empty list, preserving the previous accessor's contract. */
    public NotifyDirective {
        channels = channels == null ? List.of() : List.copyOf(channels);
    }

    public static final String IN_APP = "in-app";
    public static final String MATRIX = "matrix";
    public static final String MASTODON = "mastodon";
    public static final String EMAIL = "email";

    /** Platform-bound channels — allowed only when the action's platform matches. */
    private static final Set<String> PLATFORM_BOUND = Set.of(MATRIX, MASTODON);
    /** Always-allowed channels regardless of the action's platform. */
    private static final Set<String> ALWAYS_ALLOWED = Set.of(IN_APP, EMAIL);

    /** An empty directive — no external notification requested. */
    public static NotifyDirective none() {
        return new NotifyDirective(List.of(), false);
    }

    /**
     * Resolve a raw moderator request into a service-scoped directive.
     *
     * @param platform  the action's platform (e.g. {@code matrix}, {@code mastodon},
     *                  {@code profile}) — channel scope is judged against it
     * @param requested the raw requested channel names (may be null/empty)
     * @param emailOnly  when true, force the result to {@code email}+{@code in-app}
     */
    public static NotifyDirective resolve(String platform, List<String> requested, boolean emailOnly) {
        String p = platform == null ? "" : platform.trim().toLowerCase(Locale.ROOT);
        if (emailOnly) {
            // Forced low-noise: exactly email + in-app, regardless of the requested list.
            return new NotifyDirective(List.of(IN_APP, EMAIL), true);
        }
        if (requested == null || requested.isEmpty()) {
            return none();
        }
        Set<String> out = new LinkedHashSet<>();
        for (String raw : requested) {
            if (raw == null) {
                continue;
            }
            String ch = raw.trim().toLowerCase(Locale.ROOT);
            if (ch.isEmpty()) {
                continue;
            }
            if (ALWAYS_ALLOWED.contains(ch)) {
                out.add(ch);
            } else if (PLATFORM_BOUND.contains(ch) && ch.equals(p)) {
                // SERVICE-SCOPED: a platform-bound channel is only honoured when the
                // action's own platform matches it. Off-scope requests are dropped.
                out.add(ch);
            }
            // anything else (unknown channel, or a platform-bound channel off the action's
            // platform) is silently DROPPED — the directive can never widen beyond scope.
        }
        return new NotifyDirective(new ArrayList<>(out), false);
    }

    /** True iff this directive requests at least one channel. */
    public boolean any() {
        return channels != null && !channels.isEmpty();
    }

    /** The CSV form persisted in {@code mod_action.notify_channels} (null when empty). */
    public String toCsv() {
        return any() ? String.join(",", channels) : null;
    }
}
