package net.hugmesh.modbff.audit;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Container-free API&lt;-&gt;DB parity: the vocabulary the LAST changelog to redefine
 * {@code ck_mod_action_action} / {@code ck_mod_action_platform} (rollback blocks
 * excluded) allows must contain every {@link ModActionType} constant and the platform
 * each one is written under. A verb added without a CHECK widen fails here instead of at
 * the first runtime INSERT. (The Postgres-backed {@code ModActionOwncastTypesTest} proves
 * the same over a real database; this one needs no Docker.)
 */
class ModActionChangelogParityTest {

    private static final Path CHANGELOG = Path.of("src/main/resources/db/changelog");
    private static final Pattern INCLUDE = Pattern.compile("<include file=\"db/changelog/([^\"]+)\"");
    private static final Pattern ROLLBACK = Pattern.compile("<rollback>.*?</rollback>", Pattern.DOTALL);
    private static final Pattern QUOTED = Pattern.compile("'([^']*)'");

    /** The quoted values of the last {@code <column> IN (...)} CHECK on {@code constraint}. */
    private static Set<String> finalCheck(String constraint, String column) throws IOException {
        Pattern check = Pattern.compile(constraint + "\\s+CHECK\\s*\\(\\s*" + column
                + "\\s+IN\\s*\\((.*?)\\)\\s*\\)", Pattern.DOTALL);
        Set<String> last = null;
        Matcher inc = INCLUDE.matcher(Files.readString(CHANGELOG.resolve("db.changelog-master.xml")));
        while (inc.find()) {
            String xml = ROLLBACK.matcher(Files.readString(CHANGELOG.resolve(inc.group(1)))).replaceAll("");
            Matcher m = check.matcher(xml);
            while (m.find()) {
                Set<String> values = new LinkedHashSet<>();
                Matcher q = QUOTED.matcher(m.group(1));
                while (q.find()) values.add(q.group(1));
                last = values;
            }
        }
        assertThat(last).as("a changelog defining " + constraint).isNotNull();
        return last;
    }

    private static List<String> modActionTypeConstants() throws IllegalAccessException {
        List<String> out = new ArrayList<>();
        for (Field f : ModActionType.class.getDeclaredFields()) {
            if (Modifier.isStatic(f.getModifiers()) && f.getType() == String.class) {
                out.add((String) f.get(null));
            }
        }
        return out;
    }

    @Test
    void everyModActionTypeConstant_isAllowedByTheFinalActionCheck() throws Exception {
        assertThat(finalCheck("ck_mod_action_action", "action"))
                .containsAll(modActionTypeConstants());
    }

    @Test
    void everyConstantPlatform_isAllowedByTheFinalPlatformCheck() throws Exception {
        Set<String> platforms = finalCheck("ck_mod_action_platform", "platform");
        for (String verb : modActionTypeConstants()) {
            String prefix = verb.substring(0, verb.indexOf('.'));
            String platform = switch (prefix) {
                case "access" -> "access";
                case "domain" -> "domain-lock";
                default -> prefix;
            };
            assertThat(platforms).as("platform of " + verb).contains(platform);
        }
    }

    @Test
    void tubeHide_isInTheClosedVocabulary() throws Exception {
        assertThat(ModActionType.TUBE_HIDE).isEqualTo("tube.hide");
        assertThat(finalCheck("ck_mod_action_action", "action")).contains("tube.hide");
        assertThat(finalCheck("ck_mod_action_platform", "platform")).contains("tube");
    }
}
