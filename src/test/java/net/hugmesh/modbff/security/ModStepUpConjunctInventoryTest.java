package net.hugmesh.modbff.security;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import net.hugmesh.modbff.ModController;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DRIFT GUARD — the two lists of "which endpoints require step-up" must stay one list.
 *
 * <p>{@link ModStepUpAccessDeniedHandler} can only tell a step-up refusal from a role refusal
 * by knowing which request shapes carry the {@code @modStepUpGate.satisfied(authentication)}
 * conjunct, and a denial carries no record of which conjunct failed. That knowledge therefore
 * lives twice: once in the {@code @PreAuthorize} expressions on {@link ModController}, once in
 * {@link ModStepUpGate#SENSITIVE_WRITES}. A sixth gated endpoint added to only the first would
 * deny WITHOUT a signal — exactly the defect #16 is about, re-introduced silently — and an
 * entry added to only the second would advertise a step-up requirement for a shape that has
 * none.
 *
 * <p>This test derives BOTH sets reflectively at runtime (annotation expressions on one side,
 * the constant on the other) and fails if they differ, so neither list can move alone. It is
 * deliberately NOT a source-text scan: it reads the annotations the framework actually
 * evaluates.
 */
class ModStepUpConjunctInventoryTest {

    /** The SpEL fragment that makes a mapping step-up-gated. */
    private static final String CONJUNCT = "@modStepUpGate.satisfied";

    /** One mapping, reduced to the shape the access-denied handler matches on. */
    private record Shape(HttpMethod method, Set<String> paths) {}

    @Test
    void everyStepUpGatedMapping_isDeclaredInSensitiveWrites_andViceVersa() {
        Set<Shape> fromAnnotations = gatedMappingShapes();
        Set<Shape> fromConstant = declaredShapes();

        assertThat(fromAnnotations)
                .describedAs("mappings carrying %s on ModController", CONJUNCT)
                .isNotEmpty();
        assertThat(fromAnnotations)
                .describedAs("ModStepUpGate.SENSITIVE_WRITES must name exactly the mappings that "
                        + "carry the step-up conjunct — otherwise a gated denial ships with no "
                        + "X-Step-Up-Required signal, or an ungated one falsely claims to need "
                        + "a second factor")
                .containsExactlyInAnyOrderElementsOf(fromConstant);
    }

    /** Sanity: the declared shapes are well-formed and self-describing. */
    @Test
    void everyDeclaredSensitiveWrite_isUnderTheModSurface_andCarriesAVerb() {
        assertThat(ModStepUpGate.SENSITIVE_WRITES).isNotEmpty();
        for (ModStepUpGate.SensitiveWrite w : ModStepUpGate.SENSITIVE_WRITES) {
            assertThat(w.verb()).isNotBlank();
            assertThat(w.pathPatterns()).isNotEmpty();
            for (String p : w.pathPatterns()) {
                assertThat(p).startsWith("/bff/mod/");
            }
        }
    }

    /** The flavour this BFF advertises must satisfy the platform's own tripwire shape, or the
     *  client ignores the structured leg and silently falls back to the phrase. */
    @Test
    void theAdvertisedFlavour_matchesThePlatformHeaderShape() {
        assertThat(ModStepUpGate.STEP_UP_HEADER).matches("^X-[A-Za-z0-9-]{1,60}-StepUp$");
    }

    // ── derivation ─────────────────────────────────────────────────────────────

    private static Set<Shape> gatedMappingShapes() {
        String prefix = classPathPrefix();
        Set<Shape> shapes = new LinkedHashSet<>();
        for (Method m : ModController.class.getDeclaredMethods()) {
            PreAuthorize pre = m.getAnnotation(PreAuthorize.class);
            if (pre == null || !pre.value().contains(CONJUNCT)) {
                continue;
            }
            shapes.add(shapeOf(m, prefix));
        }
        return shapes;
    }

    private static Set<Shape> declaredShapes() {
        Set<Shape> shapes = new LinkedHashSet<>();
        for (ModStepUpGate.SensitiveWrite w : ModStepUpGate.SENSITIVE_WRITES) {
            shapes.add(new Shape(w.method(), new TreeSet<>(w.pathPatterns())));
        }
        return shapes;
    }

    private static String classPathPrefix() {
        RequestMapping mapping = ModController.class.getAnnotation(RequestMapping.class);
        if (mapping == null || mapping.value().length == 0) {
            return "";
        }
        return mapping.value()[0];
    }

    private static Shape shapeOf(Method m, String prefix) {
        PostMapping post = m.getAnnotation(PostMapping.class);
        if (post != null) {
            return new Shape(HttpMethod.POST, fullPaths(prefix, post.value()));
        }
        DeleteMapping delete = m.getAnnotation(DeleteMapping.class);
        if (delete != null) {
            return new Shape(HttpMethod.DELETE, fullPaths(prefix, delete.value()));
        }
        GetMapping get = m.getAnnotation(GetMapping.class);
        if (get != null) {
            return new Shape(HttpMethod.GET, fullPaths(prefix, get.value()));
        }
        PutMapping put = m.getAnnotation(PutMapping.class);
        if (put != null) {
            return new Shape(HttpMethod.PUT, fullPaths(prefix, put.value()));
        }
        PatchMapping patch = m.getAnnotation(PatchMapping.class);
        if (patch != null) {
            return new Shape(HttpMethod.PATCH, fullPaths(prefix, patch.value()));
        }
        RequestMapping generic = m.getAnnotation(RequestMapping.class);
        if (generic != null && generic.method().length == 1) {
            return new Shape(HttpMethod.valueOf(generic.method()[0].name()),
                    fullPaths(prefix, generic.value()));
        }
        throw new AssertionError("step-up-gated method " + m.getName()
                + " carries no single-HTTP-method mapping this guard understands — teach it, "
                + "do not delete it");
    }

    private static Set<String> fullPaths(String prefix, String[] paths) {
        List<String> out = new ArrayList<>();
        for (String p : paths) {
            out.add(prefix + p);
        }
        return new TreeSet<>(out);
    }
}
