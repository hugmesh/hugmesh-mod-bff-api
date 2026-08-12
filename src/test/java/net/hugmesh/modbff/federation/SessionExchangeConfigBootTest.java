package net.hugmesh.modbff.federation;

import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Ships-dark contract at the WIRING level (not just the runtime-behaviour level covered
 * by {@link SessionExchangeServiceTest}/{@link BearerForwardingFilterTest}): with {@code
 * app.bff-exchange.enabled} unset (the platform-wide default), {@link SessionExchangeConfig}
 * must not even construct its beans; with it explicitly turned on, the whole graph
 * (including the parameter-name-disambiguated {@code adminBffInternalWebClient} injection
 * — see {@link SessionExchangeConfig}) must wire cleanly.
 */
class SessionExchangeConfigBootTest {

    @Nested
    @SpringBootTest
    @ActiveProfiles("test")
    class FlagUnset_DefaultPosture {

        @MockitoBean ReactiveJwtDecoder jwtDecoder;

        @Autowired ApplicationContext context;

        @Test
        void sessionExchangeServiceBean_isAbsent() {
            assertThatThrownBy(() -> context.getBean(SessionExchangeService.class))
                    .isInstanceOf(NoSuchBeanDefinitionException.class);
        }
    }

    @Nested
    @SpringBootTest(properties = "app.bff-exchange.enabled=true")
    @ActiveProfiles("test")
    class FlagEnabled_OptedIn {

        @MockitoBean ReactiveJwtDecoder jwtDecoder;

        @Autowired SessionExchangeService sessionExchangeService;
        @Autowired FederationApiClient federationApiClient;

        @Test
        void wholeExchangeGraph_wiresCleanly() {
            assertThat(sessionExchangeService).isNotNull();
            // Also proves federationWebClient (which now takes an extra ObjectProvider
            // constructor param) still constructs with the exchange service present.
            assertThat(federationApiClient).isNotNull();
        }
    }
}
