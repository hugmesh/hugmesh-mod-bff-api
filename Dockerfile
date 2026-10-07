# syntax=docker/dockerfile:1.7
# -----------------------------------------------------------------------------
# Multi-stage build for hugmesh-mod-bff-api.
#
# PRIVATE DEPENDENCY (hugmesh-commons): this service now depends on
# net.hugmesh:hugmesh-commons (managed by hugmesh-parent), which is NOT
# on Maven Central — it lives in the org's GitLab Maven Package Registry. The build
# stage resolves it via the committed `settings.xml` (the `gitlab-maven` repo) using
# the GitLab CI_JOB_TOKEN. The token is mounted as a BuildKit SECRET (never an ARG,
# never an ENV, never a layer), so it leaves no trace in the image history.
#
#   GitLab CI passes it as:  --secret id=ci_job_token,env=CI_JOB_TOKEN
#                            --build-arg CI_API_V4_URL --build-arg GITLAB_GROUP_ID
# -----------------------------------------------------------------------------
FROM eclipse-temurin:25-jdk AS build
WORKDIR /work

# GitLab registry coordinates the settings.xml interpolates ($CI_API_V4_URL is the
# instance API base; GITLAB_GROUP_ID selects the org group whose package registry
# holds hugmesh-parent/hugmesh-commons).
ARG CI_API_V4_URL
ARG GITLAB_GROUP_ID
# GitHub Packages login name for the packages_read_token secret below. Only a name, not
# a credential, so an ARG is fine; defaults to "hugmesh" in the RUN when unset.
ARG UPSTREAM_PACKAGES_ACTOR
ENV CI_API_V4_URL=${CI_API_V4_URL} \
    GITLAB_GROUP_ID=${GITLAB_GROUP_ID}

COPY . .

# TWO REGISTRY CONTRACTS, SELECTED BY WHICH SECRET IS MOUNTED
#   * No packages_read_token secret (GitLab CI, the compose / kind local lane): exactly the
#     historical build, `-s settings.xml` against the GitLab group registry. Unchanged.
#   * packages_read_token present (GitHub release workflow): `-s .github/maven-ci-settings.xml`
#     against GitHub Packages (maven.pkg.github.com/hugmesh/*), authenticated with that
#     read:packages token. The token is a BuildKit secret too: never an ARG/ENV, never a layer.
# `sh -euc`, NOT `-euxc`: xtrace would print `export UPSTREAM_PACKAGES_TOKEN=<value>` into the
# BuildKit log, and the build-record artifact build-push-action uploads holds raw BuildKit logs,
# which runner-side secret masking does not cover.
#
# Resolve + build. CI_JOB_TOKEN is read from a BuildKit secret file and exported only
# for the lifetime of this RUN (so it is never persisted). `-s settings.xml` points
# Maven at the gitlab-maven registry for the private hugmesh-commons artifact.
RUN --mount=type=secret,id=ci_job_token \
    --mount=type=secret,id=packages_read_token \
    sh -euc '\
      if [ -f /run/secrets/ci_job_token ]; then \
        export CI_JOB_TOKEN="$(cat /run/secrets/ci_job_token)"; \
      fi; \
      if [ -f /run/secrets/packages_read_token ]; then \
        export UPSTREAM_PACKAGES_TOKEN="$(cat /run/secrets/packages_read_token)"; \
        export UPSTREAM_PACKAGES_ACTOR="${UPSTREAM_PACKAGES_ACTOR:-hugmesh}"; \
        ./mvnw -B -s .github/maven-ci-settings.xml package -DskipTests; \
      else \
        ./mvnw -B -s settings.xml package -DskipTests; \
      fi'

FROM eclipse-temurin:25-jre
# curl is required by this image's docker-compose HEALTHCHECK (actuator/health/readiness);
# eclipse-temurin's jre base does not ship it, which silently breaks every
# `depends_on: condition: service_healthy` gate on a fresh compose boot.
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /work/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
