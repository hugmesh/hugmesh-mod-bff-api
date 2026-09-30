package net.hugmesh.modbff.external;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Decision 83b (operator, 2026-09-23, answer B, against the item's own recommendation):
 * the ADMIN-only, one-way Matrix user deactivate lives in hugmesh-admin-bff-api
 * ({@code POST /bff/admin/matrix/deactivations/propose} then {@code .../confirm},
 * hugmesh-admin-bff-api#115), and mod-bff's own copy of the transport is RETIRED
 * (hugmesh-mod-bff-api#23).
 *
 * <p>WHY THIS PIN EXISTS. Before this change {@link MatrixAdminClient} still carried
 * {@code blockUser} + {@code DEACTIVATE_COMMAND} ({@code "!admin users deactivate "}),
 * unreachable from {@code ModService} since decision 51 but one call site away from
 * making a moderator's Matrix block permanent again (tuwunel has no
 * {@code !admin users activate}). A second, dormant copy of an irreversible verb in a
 * MOD-facing service is exactly what 83b removes, so its return must fail the build.
 *
 * <p>TWO HALVES. Reflection pins the class shape: the only public verb left is
 * {@code blockInstance}, no member is named after a user block or a deactivate, and no
 * string constant carries the tuwunel verb. The reflection half cannot see a copy that was
 * renamed or moved to another class, so a source scan of {@code src/main/java} (comments
 * stripped, string literals kept) asserts the admin-room verb text
 * {@code users deactivate} is not spelled in code anywhere in this service. Comments are
 * excluded on purpose: the javadoc still has to be able to say what was removed and where
 * it went.
 */
class MatrixAdminClientNoUserDeactivateTest {

    /** The tuwunel admin-room verb text, matched case-insensitively and whitespace-folded. */
    private static final String VERB = "users deactivate";

    @Test
    void matrixAdminClient_exposesBlockInstanceAsItsOnlyPublicVerb() {
        List<String> publicMethods = Arrays.stream(MatrixAdminClient.class.getDeclaredMethods())
                .filter(m -> Modifier.isPublic(m.getModifiers()) && !m.isSynthetic())
                .map(Method::getName)
                .sorted()
                .toList();
        assertThat(publicMethods)
                .as("public verbs of MatrixAdminClient — a user block/deactivate belongs to "
                        + "hugmesh-admin-bff-api since decision 83b (hugmesh-mod-bff-api#23)")
                .containsExactly("blockInstance");
    }

    @Test
    void matrixAdminClient_declaresNoUserBlockOrDeactivateMember() {
        List<String> offending = new ArrayList<>();
        for (Method m : MatrixAdminClient.class.getDeclaredMethods()) {
            if (namesUserDeactivate(m.getName())) {
                offending.add("method " + m.getName());
            }
        }
        for (Field f : MatrixAdminClient.class.getDeclaredFields()) {
            if (namesUserDeactivate(f.getName())) {
                offending.add("field " + f.getName());
            }
        }
        assertThat(offending)
                .as("MatrixAdminClient members named after a user block or a deactivate")
                .isEmpty();
    }

    @Test
    void matrixAdminClient_holdsNoStringConstantCarryingTheDeactivateVerb() throws IllegalAccessException {
        List<String> offending = new ArrayList<>();
        for (Field f : MatrixAdminClient.class.getDeclaredFields()) {
            if (Modifier.isStatic(f.getModifiers()) && f.getType() == String.class) {
                f.setAccessible(true);
                Object value = f.get(null);
                if (value instanceof String s && carriesVerb(s)) {
                    offending.add(f.getName() + "=" + s);
                }
            }
        }
        assertThat(offending)
                .as("static String constants of MatrixAdminClient carrying '%s'", VERB)
                .isEmpty();
    }

    @Test
    void mainSources_spellTheDeactivateVerbNowhereOutsideComments() throws IOException {
        Path root = Paths.get("src", "main", "java");
        assertThat(root).as("main source root (surefire runs from the module dir)").isDirectory();
        List<Path> sources;
        try (Stream<Path> walk = Files.walk(root)) {
            sources = walk.filter(p -> p.toString().endsWith(".java")).sorted().toList();
        }
        // Non-vacuous: the scan must actually cover the client it is about.
        assertThat(sources)
                .as("scanned sources")
                .anyMatch(p -> p.getFileName().toString().equals("MatrixAdminClient.java"));
        List<String> offending = new ArrayList<>();
        for (Path p : sources) {
            String code = stripComments(Files.readString(p, StandardCharsets.UTF_8));
            if (carriesVerb(code)) {
                offending.add(root.relativize(p).toString());
            }
        }
        assertThat(offending)
                .as("main sources that spell '%s' in code or a string literal", VERB)
                .isEmpty();
    }

    /** Self-test of the comment stripper, so the scan above cannot pass by eating code. */
    @Test
    void stripComments_keepsCodeAndStringLiterals_dropsCommentsOnly() {
        String src = "a /* users deactivate */ b // users deactivate\n"
                + "String u = \"http://x\"; String v = \"!admin users  deactivate \";\n"
                + "char c = '\"'; String w = \"/* not a comment */\";\n"
                + "String t = \"\"\"\n  users deactivate\n  \"\"\";";
        String out = stripComments(src);
        assertThat(out).startsWith("a   b").contains("\"http://x\"")
                .contains("\"!admin users  deactivate \"")
                .contains("\"/* not a comment */\"")
                .contains("users deactivate\n  \"\"\"");
        assertThat(carriesVerb(out)).isTrue();
        assertThat(carriesVerb(stripComments("x /* users deactivate */ y // users deactivate"))).isFalse();
    }

    private static boolean namesUserDeactivate(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        return n.contains("deactivat") || n.contains("blockuser") || n.contains("block_user");
    }

    private static boolean carriesVerb(String text) {
        return text.toLowerCase(Locale.ROOT).replaceAll("\\s+", " ").contains(VERB);
    }

    /**
     * Drops {@code //} and {@code /* *}{@code /} comments and keeps everything else,
     * including string, text-block and char literals (so {@code "http://x"} is not
     * mistaken for a line comment and a literal carrying the verb is still seen).
     */
    static String stripComments(String src) {
        StringBuilder out = new StringBuilder(src.length());
        int i = 0;
        int n = src.length();
        while (i < n) {
            char c = src.charAt(i);
            char next = i + 1 < n ? src.charAt(i + 1) : '\0';
            if (c == '/' && next == '/') {
                while (i < n && src.charAt(i) != '\n') {
                    i++;
                }
            } else if (c == '/' && next == '*') {
                int end = src.indexOf("*/", i + 2);
                i = end < 0 ? n : end + 2;
                out.append(' ');
            } else if (src.startsWith("\"\"\"", i)) {
                int end = src.indexOf("\"\"\"", i + 3);
                int stop = end < 0 ? n : end + 3;
                out.append(src, i, stop);
                i = stop;
            } else if (c == '"' || c == '\'') {
                int j = i + 1;
                while (j < n && src.charAt(j) != c && src.charAt(j) != '\n') {
                    j += src.charAt(j) == '\\' ? 2 : 1;
                }
                int stop = Math.min(j + 1, n);
                out.append(src, i, stop);
                i = stop;
            } else {
                out.append(c);
                i++;
            }
        }
        return out.toString();
    }
}
