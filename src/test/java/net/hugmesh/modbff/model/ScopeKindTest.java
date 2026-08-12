package net.hugmesh.modbff.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link ScopeKind} contract: the enum is a CODE-SIDE lens over the closed server-wide-block
 * scope vocabulary, and its wire form is BYTE-IDENTICAL to the prior lowercase
 * {@code "user"/"instance"} strings exchanged on the {@code BlockRequest} {@code scope} field.
 * These tests pin that equivalence so the enum can never silently drift the DTO/JSON value, and
 * specifically that {@code USER == fromWire(scope)} reproduces the prior
 * {@code "user".equals(scope)} boolean {@code ModService.block} used.
 */
class ScopeKindTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void value_isTheExactLowercaseWireToken() {
        assertThat(ScopeKind.USER.value()).isEqualTo("user");
        assertThat(ScopeKind.INSTANCE.value()).isEqualTo("instance");
    }

    @Test
    void values_areExactlyTheClosedSet_inOrder() {
        assertThat(java.util.Arrays.stream(ScopeKind.values()).map(ScopeKind::value).toList())
                .containsExactly("user", "instance");
    }

    @Test
    void fromWire_roundTripsEveryToken() {
        for (ScopeKind k : ScopeKind.values()) {
            assertThat(ScopeKind.fromWire(k.value())).isEqualTo(k);
        }
    }

    @Test
    void userEquals_reproducesThePriorBooleanBranch() {
        // ModService.block used `boolean user = "user".equals(scope)`; the enum form
        // `USER == fromWire(scope)` must give the IDENTICAL verdict on every input.
        for (String scope : new String[] {"user", "instance", "USER", "User", "", "bogus", null}) {
            boolean prior = "user".equals(scope);
            boolean now = ScopeKind.USER == ScopeKind.fromWire(scope);
            assertThat(now).as("scope=%s", scope).isEqualTo(prior);
        }
    }

    @Test
    void fromWire_isNullTolerant_forNullAndUnknown() {
        assertThat(ScopeKind.fromWire(null)).isNull();
        assertThat(ScopeKind.fromWire("")).isNull();
        assertThat(ScopeKind.fromWire("server")).isNull();
        assertThat(ScopeKind.fromWire("USER")).isNull();   // case-sensitive: the wire token is lowercase
        assertThat(ScopeKind.fromWire("Instance")).isNull();
    }

    @Test
    void isValid_acceptsOnlyTheTwoTokens() {
        assertThat(ScopeKind.isValid("user")).isTrue();
        assertThat(ScopeKind.isValid("instance")).isTrue();
        assertThat(ScopeKind.isValid("server")).isFalse();
        assertThat(ScopeKind.isValid(null)).isFalse();
        assertThat(ScopeKind.isValid("USER")).isFalse();
    }

    @Test
    void json_serializesToLowercaseToken() throws Exception {
        assertThat(MAPPER.writeValueAsString(ScopeKind.USER)).isEqualTo("\"user\"");
        assertThat(MAPPER.writeValueAsString(ScopeKind.INSTANCE)).isEqualTo("\"instance\"");
    }

    @Test
    void json_deserializesFromLowercaseToken() throws Exception {
        assertThat(MAPPER.readValue("\"user\"", ScopeKind.class)).isEqualTo(ScopeKind.USER);
        assertThat(MAPPER.readValue("\"instance\"", ScopeKind.class)).isEqualTo(ScopeKind.INSTANCE);
    }

    @Test
    void json_unknownTokenDeserializesToNull_neverThrows() throws Exception {
        assertThat(MAPPER.readValue("\"nope\"", ScopeKind.class)).isNull();
    }
}
