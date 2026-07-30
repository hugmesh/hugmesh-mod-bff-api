package systems.hugmesh.modbff.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The closed set of server-wide BLOCK scope kinds — the WHO/WHAT a {@code matrix}/{@code mastodon}
 * block applies to. This is a genuinely CLOSED vocabulary: it is pinned by the
 * {@code BlockRequest} {@code @Pattern} regex ({@code (?i)user|instance}), accepting exactly the
 * lowercase tokens {@code user | instance}.
 *
 * <h2>Wire form is BYTE-IDENTICAL to the prior {@code String} ("user"/"instance")</h2>
 * Each constant carries the EXACT lowercase token the system has always exchanged. The request
 * DTO still binds {@code scope} as a {@code String} (the {@code @Pattern} bean-validation runs on
 * the raw String), so this enum is a CODE-SIDE lens, never a wire/column type change.
 * {@link #value()} is annotated {@link JsonValue} (emits the lowercase token, not the Java
 * constant name) and {@link #fromWire(String)} is a null-tolerant {@link JsonCreator} parsing the
 * same tokens back — the round-trip is wire-safe by construction.
 *
 * <p>{@code ModService.block} previously collapsed the scope to a bare boolean
 * ({@code boolean user = "user".equals(scope)}); routing it through {@link #USER} makes the
 * user-vs-instance branch self-documenting without changing a single transmitted value.
 */
public enum ScopeKind {

    /** Block a single user (MXID / acct) on the platform. */
    USER("user"),
    /** Block a whole instance/domain on the platform. */
    INSTANCE("instance");

    private final String value;

    ScopeKind(String value) {
        this.value = value;
    }

    /** The exact lowercase wire token ({@code user | instance}) — the DTO/JSON form. */
    @JsonValue
    public String value() {
        return value;
    }

    /**
     * Parse a wire token ({@code user | instance}) to its {@link ScopeKind}, or {@code null}
     * when the token is null / unrecognised. Null-tolerant by design: the block path treats a
     * non-{@code user} value as the instance branch (the prior {@code "user".equals(scope)}
     * boolean), so this parse never throws on a stray value — the bean-validation
     * {@code @Pattern} on the raw String at the DTO edge is the actual reject gate.
     */
    @JsonCreator
    public static ScopeKind fromWire(String wire) {
        if (wire == null) {
            return null;
        }
        for (ScopeKind k : values()) {
            if (k.value.equals(wire)) {
                return k;
            }
        }
        return null;
    }

    /**
     * True iff {@code wire} is one of the two valid lowercase scope tokens. The typed
     * equivalent of the {@code @Pattern} membership test.
     */
    public static boolean isValid(String wire) {
        return fromWire(wire) != null;
    }
}
