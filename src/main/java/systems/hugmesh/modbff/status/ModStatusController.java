package systems.hugmesh.modbff.status;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import reactor.core.publisher.Mono;
import systems.hugmesh.modbff.security.Roles;

import java.util.List;
import java.util.Map;

/**
 * Polling endpoint for the calling moderator's own status — active roles and domain.
 * Derived entirely from the already-validated JWT authorities (owner == JWT subject,
 * no BOLA). No DB query: the Spring Security filter chain has already converted the JWT.
 *
 * <p>GET {@code /bff/mod/status} — call at whatever interval the UI prefers to detect
 * role changes (e.g. a ROLE_MOD grant/revoke reflects on the next token refresh).
 */
@Tag(name = "Moderator status", description = "Polling endpoint for the caller's own moderator role status.")
@RestController
@RequestMapping("/bff/mod")
@PreAuthorize("hasAnyRole('MOD','ADMIN','SUPERADMIN')")
public class ModStatusController {

    @Operation(operationId = "getModStatus",
            summary = "Caller's own moderator status — active roles and domain scope.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Status returned — sub, domain, and active ROLE_* list"),
            @ApiResponse(responseCode = "401", description = "Unauthenticated", content = @Content),
            @ApiResponse(responseCode = "403", description = "Caller lacks ROLE_MOD, ROLE_ADMIN, or ROLE_SUPERADMIN", content = @Content),
            @ApiResponse(responseCode = "500", description = "Unexpected server error", content = @Content)
    })
    @GetMapping("/status")
    public Mono<Map<String, Object>> status(Authentication auth) {
        String sub = auth.getName();
        String domain = Roles.domainOf(auth);
        List<String> roles = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(a -> a.startsWith("ROLE_"))
                .map(a -> a.substring("ROLE_".length()))
                .toList();
        return Mono.just(Map.of(
                "sub", sub,
                "domain", domain != null ? domain : "default",
                "roles", roles));
    }
}
