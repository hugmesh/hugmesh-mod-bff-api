package net.hugmesh.modbff.support;

import liquibase.integration.spring.SpringLiquibase;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;

/**
 * Runs the PRODUCTION Liquibase changelog over the Testcontainers-Postgres database that
 * {@link net.hugmesh.commons.testsupport.PostgresTestSupport} provisions, for the
 * {@code @DataR2dbcTest} audit-repository SLICES.
 *
 * <p>WHY a dedicated config (vs. the full-context boot tests): a {@code @DataR2dbcTest}
 * slice auto-configures ONLY the reactive R2DBC stack — it does NOT load Spring Boot's
 * Liquibase auto-configuration — and the {@code test} profile disables Liquibase outright
 * ({@code spring.liquibase.enabled=false}). So the slice would run its R2DBC queries
 * against an EMPTY schema. This {@code @TestConfiguration} re-adds a {@link SpringLiquibase}
 * bean (Liquibase has no R2DBC runner, so it uses a JDBC datasource) pointed at the SAME
 * container db that {@code PostgresTestSupport.@DynamicPropertySource} published into
 * {@code spring.liquibase.*}. The reactive {@code ConnectionFactory} the slice wires from
 * {@code spring.r2dbc.*} resolves to the same db, so the repository runs against the real
 * Liquibase-applied schema — now including changelog 009 ({@code pgcrypto} +
 * {@code gen_random_uuid()} DEFAULT) and {@code INSERT ... RETURNING}, NEITHER of which the
 * old H2 PostgreSQL-compat store ({@code TestDatabaseConfig}) could honour. That is exactly
 * why the DB-generated-UUID-PK exemplar moves these slices to Testcontainers-Postgres.
 *
 * <p>This mirrors the former {@code TestDatabaseConfig} shape (a Liquibase bean + a
 * datasource) but targets the real Postgres container instead of H2.
 */
@TestConfiguration(proxyBeanMethods = false)
public class PostgresSliceTestConfig {

    /** JDBC datasource at the container db published by PostgresTestSupport's
     *  {@code spring.liquibase.*} dynamic properties (Liquibase runs over JDBC). */
    @Bean
    public DataSource liquibaseDataSource(
            @Value("${spring.liquibase.url}") String url,
            @Value("${spring.liquibase.user}") String user,
            @Value("${spring.liquibase.password}") String password) {
        DriverManagerDataSource ds = new DriverManagerDataSource();
        ds.setDriverClassName("org.postgresql.Driver");
        ds.setUrl(url);
        ds.setUsername(user);
        ds.setPassword(password);
        return ds;
    }

    /** Apply the production changelog over the container db BEFORE the reactive
     *  repository runs (the slice depends on this bean transitively). */
    @Bean
    public SpringLiquibase liquibase(DataSource liquibaseDataSource) {
        SpringLiquibase lb = new SpringLiquibase();
        lb.setDataSource(liquibaseDataSource);
        lb.setChangeLog("classpath:db/changelog/db.changelog-master.xml");
        return lb;
    }
}
