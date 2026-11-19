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
ENV CI_API_V4_URL=${CI_API_V4_URL} \
    GITLAB_GROUP_ID=${GITLAB_GROUP_ID}

COPY . .

# Resolve + build. CI_JOB_TOKEN is read from a BuildKit secret file and exported only
# for the lifetime of this RUN (so it is never persisted). `-s settings.xml` points
# Maven at the gitlab-maven registry for the private hugmesh-commons artifact.
# SECOND REGISTRY PATH (GitHub Actions release.yml). When the BuildKit secret
# `packages_read_token` is mounted, the net.hugmesh libraries are resolved from GitHub
# Packages through .github/maven-ci-settings.xml (credential: UPSTREAM_PACKAGES_ACTOR build
# arg + the secret as UPSTREAM_PACKAGES_TOKEN) instead of the GitLab registry in settings.xml.
# With no such secret the legacy GitLab path below is unchanged, which is what GitLab CI and
# the local compose lane (m2-bootstrap.sh) rely on. A secret that is mounted but EMPTY is an
# error, not a silent fall-back to the GitLab path (it would die later as "/groups//").
# `set -x` is deliberately absent: it would echo the exported token into the build log.
ARG UPSTREAM_PACKAGES_ACTOR=github-actions
RUN --mount=type=secret,id=ci_job_token \
    --mount=type=secret,id=packages_read_token \
    sh -euc '\
      settings=settings.xml; \
      if [ -e /run/secrets/packages_read_token ]; then \
        if [ ! -s /run/secrets/packages_read_token ]; then \
          echo "FATAL: secret packages_read_token is mounted but empty (is PACKAGES_READ_TOKEN set?)" >&2; \
          exit 1; \
        fi; \
        UPSTREAM_PACKAGES_TOKEN="$(cat /run/secrets/packages_read_token)"; \
        export UPSTREAM_PACKAGES_TOKEN UPSTREAM_PACKAGES_ACTOR; \
        settings=.github/maven-ci-settings.xml; \
      elif [ -f /run/secrets/ci_job_token ]; then \
        CI_JOB_TOKEN="$(cat /run/secrets/ci_job_token)"; \
        export CI_JOB_TOKEN; \
      fi; \
      echo "maven settings: ${settings}"; \
      ./mvnw -B -s "${settings}" package -DskipTests'

FROM eclipse-temurin:25-jre
# curl is required by this image's docker-compose HEALTHCHECK (actuator/health/readiness);
# eclipse-temurin's jre base does not ship it, which silently breaks every
# `depends_on: condition: service_healthy` gate on a fresh compose boot.
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /work/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
