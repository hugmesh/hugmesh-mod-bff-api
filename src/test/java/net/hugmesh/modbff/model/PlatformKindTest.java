package net.hugmesh.modbff.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link PlatformKind} contract: the enum is a CODE-SIDE lens over the closed moderation
 * platform vocabulary, and its wire form is BYTE-IDENTICAL to the prior lowercase
 * {@code "matrix"/"mastodon"/"profile"} strings the system stored (the
 * {@code mod_action.platform} column / {@code ck_mod_action_platform} CHECK) and exchanged
 * (the {@code BanRequest}/{@code BlockRequest} {@code platform} field). These tests pin that
 * equivalence so the enum can never silently drift the DB/JSON value.
 */
class PlatformKindTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void value_isTheExactLowercaseWireToken() {
        // The stored/transmitted token is the lowercase form, NOT the Java constant name.
        assertThat(PlatformKind.MATRIX.value()).isEqualTo("matrix");
        assertThat(PlatformKind.MASTODON.value()).isEqualTo("mastodon");
        assertThat(PlatformKind.PROFILE.value()).isEqualTo("profile");
    }

    @Test
    void values_areExactlyTheClosedSet_inOrder() {
        // The closed set is exactly the three ban platforms, in the documented order.
        assertThat(java.util.Arrays.stream(PlatformKind.values()).map(PlatformKind::value).toList())
                .containsExactly("matrix", "mastodon", "profile");
    }

    @Test
    void fromWire_roundTripsEveryToken() {
        for (PlatformKind k : PlatformKind.values()) {
            // value() -> fromWire() returns the SAME constant (round-trip identity).
            assertThat(PlatformKind.fromWire(k.value())).isEqualTo(k);
        }
    }

    @Test
    void fromWire_isNullTolerant_forNullAndUnknown() {
        // A null / unknown / wrong-case token maps to null. The service switches treat null as
        // their default fall-through (no-op / 400 on the ban path), exactly the prior
        // string-equals fall-through behaviour. Case matters: the column/wire token is lowercase.
        assertThat(PlatformKind.fromWire(null)).isNull();
        assertThat(PlatformKind.fromWire("")).isNull();
        assertThat(PlatformKind.fromWire("instance")).isNull();
        assertThat(PlatformKind.fromWire("MATRIX")).isNull();   // case-sensitive: the column is lowercase
        assertThat(PlatformKind.fromWire("Matrix")).isNull();
    }

    @Test
    void isValid_acceptsOnlyTheThreeTokens() {
        assertThat(PlatformKind.isValid("matrix")).isTrue();
        assertThat(PlatformKind.isValid("mastodon")).isTrue();
        assertThat(PlatformKind.isValid("profile")).isTrue();
        assertThat(PlatformKind.isValid("instance")).isFalse();
        assertThat(PlatformKind.isValid(null)).isFalse();
        assertThat(PlatformKind.isValid("MATRIX")).isFalse();
    }

    @Test
    void json_serializesToLowercaseToken() throws Exception {
        // @JsonValue => the enum serializes to its lowercase wire token, never "MATRIX".
        assertThat(MAPPER.writeValueAsString(PlatformKind.MATRIX)).isEqualTo("\"matrix\"");
        assertThat(MAPPER.writeValueAsString(PlatformKind.MASTODON)).isEqualTo("\"mastodon\"");
        assertThat(MAPPER.writeValueAsString(PlatformKind.PROFILE)).isEqualTo("\"profile\"");
    }

    @Test
    void json_deserializesFromLowercaseToken() throws Exception {
        // @JsonCreator(fromWire) => the lowercase token parses back to the constant.
        assertThat(MAPPER.readValue("\"matrix\"", PlatformKind.class)).isEqualTo(PlatformKind.MATRIX);
        assertThat(MAPPER.readValue("\"mastodon\"", PlatformKind.class)).isEqualTo(PlatformKind.MASTODON);
        assertThat(MAPPER.readValue("\"profile\"", PlatformKind.class)).isEqualTo(PlatformKind.PROFILE);
    }

    @Test
    void json_unknownTokenDeserializesToNull_neverThrows() throws Exception {
        // An unrecognised token is tolerated (null), mirroring the read-path leniency.
        assertThat(MAPPER.readValue("\"nope\"", PlatformKind.class)).isNull();
    }
}
