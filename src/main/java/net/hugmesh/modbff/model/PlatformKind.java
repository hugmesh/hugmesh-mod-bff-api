package net.hugmesh.modbff.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The closed set of moderation PLATFORM kinds — the WHICH-platform a ban/block acts on.
 * This is a genuinely CLOSED vocabulary: it is pinned by the {@code BanRequest}
 * {@code @Pattern} regex ({@code (?i)matrix|mastodon|profile}), the {@code BlockRequest}
 * {@code @Pattern} regex ({@code (?i)matrix|mastodon}), AND the
 * {@code ck_mod_action_platform} DB CHECK constraint, all of which accept exactly the
 * lowercase tokens {@code matrix | mastodon | profile}.
 *
 * <h2>Wire form is BYTE-IDENTICAL to the prior {@code String} ("matrix"/"mastodon"/"profile")</h2>
 * Each constant carries the EXACT lowercase token the system has always stored / exchanged:
 * <ul>
 *   <li><b>DB</b> — the {@code mod_action.platform varchar} column keeps its lowercase
 *       strings. {@code ModActionRow}/{@code ModAction} still persist a {@code String}, so
 *       R2DBC reads/writes are unchanged; this enum is a CODE-SIDE lens over that string,
 *       never a column type change.</li>
 *   <li><b>JSON / DTO</b> — the request DTOs still bind {@code platform} as a
 *       {@code String} (the {@code @Pattern} bean-validation still runs on the raw String),
 *       so this is not on any current JSON bind path. {@link #value()} is annotated
 *       {@link JsonValue} so anywhere an enum value WERE serialized it emits the lowercase
 *       token (not the Java constant name); {@link #fromWire(String)} (also a
 *       {@link JsonCreator}) parses the same tokens back — the round-trip is wire-safe by
 *       construction.</li>
 * </ul>
 *
 * <p>Routing the platform branching ({@code roleForPlatform}, {@code assertPlatformRole},
 * {@code block}'s external-call switch, {@code blockActionFor}) through this enum replaces
 * the scattered {@code "matrix".equals(...)} / {@code case "mastodon"} string literals with
 * an exhaustive, typo-proof {@code switch}, WITHOUT changing a single stored or transmitted
 * value.
 *
 * <p>NOTE the {@code matrix|mastodon}-vs-{@code profile} asymmetry is intentional and
 * preserved by the call sites, NOT by this enum: a BAN accepts all three
 * ({@link #roleForPlatform}); a server-wide BLOCK accepts only {@code matrix}/{@code mastodon}
 * (the {@code BlockRequest} {@code @Pattern} rejects {@code profile} at the edge, and the
 * block switch's {@code default} leg stays a no-op fall-through).
 */
public enum PlatformKind {

    /** Matrix homeserver platform — maps to the access role {@code ROLE_MATRIX}. */
    MATRIX("matrix"),
    /** Mastodon/Akkoma homeserver platform — maps to the access role {@code ROLE_MASTODON}. */
    MASTODON("mastodon"),
    /** Profile (account) platform — maps to the {@code PROFILE} access role. Valid for a
     *  BAN only; a server-wide BLOCK does not accept it. */
    PROFILE("profile");

    private final String value;

    PlatformKind(String value) {
        this.value = value;
    }

    /** The exact lowercase wire token ({@code matrix | mastodon | profile}) — the DB/JSON form. */
    @JsonValue
    public String value() {
        return value;
    }

    /**
     * Parse a wire token ({@code matrix | mastodon | profile}) to its {@link PlatformKind},
     * or {@code null} when the token is null / unrecognised. Null-tolerant by design: the
     * service's branching switches treat an unknown / null platform as a no-op fall-through
     * (the {@code default} legs), exactly the prior {@code case "matrix"} / {@code "matrix".equals}
     * fall-through behaviour. The bean-validation {@code @Pattern} (still on the raw String at
     * the DTO edge) is the actual reject gate; this parse never throws on a stray value.
     */
    @JsonCreator
    public static PlatformKind fromWire(String wire) {
        if (wire == null) {
            return null;
        }
        for (PlatformKind k : values()) {
            if (k.value.equals(wire)) {
                return k;
            }
        }
        return null;
    }

    /**
     * True iff {@code wire} is one of the three valid lowercase platform tokens. The typed
     * equivalent of the {@code @Pattern}/DB-CHECK membership test, kept so callers that hold a
     * raw {@code String} (the controller validation already ran, the service double-checks)
     * get the same accept/reject verdict.
     */
    public static boolean isValid(String wire) {
        return fromWire(wire) != null;
    }
}
