# HugMesh mod BFF API — developer make targets.
#
# `make pentest` mirrors the centralized OWASP pen-test CI stage
# (.gitlab-ci.yml -> generator /tests/pentest/ci/pentest-stage.gitlab-ci.yml)
# so a contributor can run the same checks locally BEFORE pushing.
#
#   * SCA  — OWASP Dependency-Check over this repo (Java/Maven).
#   * DAST — the full authenticated-ZAP + probes + nuclei harness, delegated to
#            the generator's tests/pentest/run-pentest.sh, ONLY when a target is
#            configured via DAST_TARGET_URL.
#
# This target is intentionally NON-fatal when tooling or a DAST target is absent:
# it reports what it would run and exits 0 so it stays usable on any dev box.

SHELL := /bin/bash

# Eclipse Temurin JDK image used by CI for the Maven SCA self-scan. Must track
# this repo's actual toolchain (java.version=25 via hugmesh-parent, matching
# the Dockerfile's eclipse-temurin:25-jdk build stage) — a stale JDK 21 image
# here cannot build a project pinned to Java 25.
JDK_IMAGE       ?= eclipse-temurin:25-jdk-noble
# Fail the local SCA build on a CVSS >= this (CI uses 9 for the gating mvn run).
SCA_FAIL_CVSS   ?= 9
# Where the generator pen-test harness lives (run-pentest.sh). Override if your
# checkout layout differs. Sibling HugMesh checkout is the default.
PENTEST_HARNESS_DIR ?= ../hugmesh-generator/tests/pentest
# Set to the running app's base URL to actually drive the DAST harness, e.g.
#   make pentest DAST_TARGET_URL=http://localhost:8080
DAST_TARGET_URL ?=

.PHONY: pentest pentest-sca pentest-dast

## pentest: run the repo-local SCA self-scan + (optional) the DAST harness.
pentest: pentest-sca pentest-dast

## pentest-sca: OWASP Dependency-Check over this Java/Maven repo (mirrors CI).
pentest-sca:
	@echo "==> SCA: OWASP Dependency-Check (failBuildOnCVSS=$(SCA_FAIL_CVSS))"
	@if command -v docker >/dev/null 2>&1; then \
		echo "    running via $(JDK_IMAGE) (same image the CI dependency-check job uses)"; \
		docker run --rm \
			-v "$(CURDIR):/workspace" \
			-v "$(CURDIR)/.dep-check-data:/dep-check-data" \
			-w /workspace \
			--entrypoint "" \
			$(JDK_IMAGE) \
			./mvnw org.owasp:dependency-check-maven:check \
				-Dformat=HTML,JSON \
				-DfailBuildOnCVSS=$(SCA_FAIL_CVSS) \
				-DdataDirectory=/dep-check-data \
				-DautoUpdate=true \
				-B; \
	elif [ -x ./mvnw ]; then \
		echo "    docker not found; running ./mvnw directly on the host JDK"; \
		./mvnw org.owasp:dependency-check-maven:check -DfailBuildOnCVSS=$(SCA_FAIL_CVSS) -B; \
	else \
		echo "    SKIP: neither docker nor ./mvnw available; nothing to scan here."; \
	fi

## pentest-dast: delegate the full DAST harness (ZAP + probes + nuclei) to the
## generator when DAST_TARGET_URL is set; otherwise print how to run it.
pentest-dast:
	@echo "==> DAST: authenticated ZAP baseline + custom probes + nuclei"
	@if [ -z "$(DAST_TARGET_URL)" ]; then \
		echo "    SKIP: DAST_TARGET_URL not set — no target to scan."; \
		echo "    To run against a live app:"; \
		echo "      make pentest DAST_TARGET_URL=http://localhost:8080"; \
		echo "    (delegates to $(PENTEST_HARNESS_DIR)/run-pentest.sh)"; \
	elif [ -x "$(PENTEST_HARNESS_DIR)/run-pentest.sh" ]; then \
		echo "    target=$(DAST_TARGET_URL) harness=$(PENTEST_HARNESS_DIR)/run-pentest.sh"; \
		ZAP_TARGET="$(DAST_TARGET_URL)" \
			bash "$(PENTEST_HARNESS_DIR)/run-pentest.sh" --env local --scan baseline --pipeline main; \
	else \
		echo "    harness not found at $(PENTEST_HARNESS_DIR)/run-pentest.sh"; \
		echo "    clone it alongside this repo, e.g.:"; \
		echo "      git clone https://github.com/hugmesh-net/hugmesh-generator ../hugmesh-generator"; \
		echo "    then re-run; or point PENTEST_HARNESS_DIR at your checkout."; \
	fi
