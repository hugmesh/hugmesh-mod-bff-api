#!/usr/bin/env python3
"""Tests for .github/workflows/release.yml: runs the workflow's own signref check and its
GitHub Release flag logic, extracted from the file, against each release channel. Standard
library only (no PyYAML), no network. Run: python3 scripts/test-release-workflow.py
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WF = open(os.path.join(ROOT, ".github", "workflows", "release.yml"), encoding="utf-8").read()
IMG = "ghcr.io/hugmesh/hugmesh-mod-bff-api"
DIGEST = "sha256:" + "a" * 64
FAILURES = 0


def check(desc, ok, detail=""):
    global FAILURES
    if ok:
        print(f"ok   {desc}")
    else:
        FAILURES += 1
        print(f"FAIL {desc}\n---- {detail}\n----", file=sys.stderr)


def step_block(step_id_or_name):
    """The text of one step, from its '- name:' line to the next '- name:' or job."""
    lines = WF.splitlines()
    for i, line in enumerate(lines):
        if step_id_or_name in line:
            start = i
            while not lines[start].lstrip().startswith("- name:"):
                start -= 1
            end = i + 1
            while end < len(lines) and not lines[end].lstrip().startswith("- name:") \
                    and not re.match(r"^  [a-z-]+:\s*$", lines[end]):
                end += 1
            return "\n".join(lines[start:end])
    raise SystemExit(f"step {step_id_or_name!r} not found in release.yml")


# ── the signref python, exactly as the workflow runs it ───────────────────────────────
signref = step_block("id: signref")
m = re.search(r"python3 - <<'PY'\n(.*?)\n\s*PY\n", signref + "\n", re.S)
SIGNREF_PY = textwrap.dedent(m.group(1)) if m else ""
check("signref step holds a python heredoc", bool(SIGNREF_PY))
check("signref keeps the literal `\"latest\" in tags`", '"latest" in tags' in SIGNREF_PY)
for var in ("VERSION", "CHANNEL", "EXPECTED_TAGS"):
    check(f"signref step env passes {var}", re.search(rf"^\s+{var}: \$\{{\{{ needs\.version\.outputs\.", signref, re.M) is not None)


def run_signref(version, channel, guard_tags, pushed_tags=None):
    pushed = guard_tags if pushed_tags is None else pushed_tags
    with tempfile.NamedTemporaryFile("r", delete=False) as out:
        path = out.name
    env = dict(os.environ)
    env.update({
        "METADATA": json.dumps({"image.name": ",".join(f"{IMG}:{t}" for t in pushed)}),
        "DIGEST": DIGEST,
        "EXPECTED_TAGS": ",".join(f"{IMG}:{t}" for t in guard_tags),
        "CHANNEL": channel,
        "GITHUB_OUTPUT": path,
    })
    if version is None:
        env.pop("VERSION", None)
    else:
        env["VERSION"] = version
    r = subprocess.run([sys.executable, "-I", "-c", SIGNREF_PY], env=env, capture_output=True, text=True)
    written = open(path).read()
    os.unlink(path)
    return r.returncode, r.stdout + r.stderr, written


cases = [
    # (description, version, channel, guard tags, pushed tags or None, should pass)
    ("beta: :X.Y.Z-beta.N, :sha, :beta is signed", "0.3.0-beta.1", "beta",
     ["0.3.0-beta.1", "sha-0123456789ab", "beta"], None, True),
    ("stable newest line: :X.Y.Z, :sha, :X.Y, :latest is signed", "0.3.0", "stable",
     ["0.3.0", "sha-0123456789ab", "0.3", "latest"], None, True),
    ("stable older line: :X.Y.Z, :sha, :X.Y (no :latest) is signed", "0.2.4", "stable",
     ["0.2.4", "sha-0123456789ab", "0.2"], None, True),
    ("main build: :main, :sha is signed", "0.3.0-beta.1", "none",
     ["main", "sha-0123456789ab"], None, True),
    ("release branch build: :sha only is signed", "0.2.4", "none",
     ["sha-0123456789ab"], None, True),
    ("beta that pushed :latest is refused", "0.3.0-beta.1", "beta",
     ["0.3.0-beta.1", "sha-0123456789ab", "beta", "latest"], None, False),
    ("stable that pushed :beta is refused", "0.3.0", "stable",
     ["0.3.0", "sha-0123456789ab", "0.3", "beta"], None, False),
    ("beta that pushed a floating :X.Y is refused", "0.3.0-beta.1", "beta",
     ["0.3.0-beta.1", "sha-0123456789ab", "beta", "0.3"], None, False),
    ("release-branch build that pushed :latest is refused", "0.2.4", "none",
     ["sha-0123456789ab", "latest"], None, False),
    (":latest with VERSION missing is refused (fails closed)", None, "stable",
     ["0.3.0", "sha-0123456789ab", "0.3", "latest"], None, False),
    ("a pushed tag the guard did not choose is refused", "0.3.0", "stable",
     ["0.3.0", "sha-0123456789ab", "0.3"], ["0.3.0", "sha-0123456789ab", "0.3", "latest"], False),
    ("a guard tag that was not pushed is refused", "0.3.0", "stable",
     ["0.3.0", "sha-0123456789ab", "0.3", "latest"], ["0.3.0", "sha-0123456789ab", "0.3"], False),
]
for desc, version, channel, guard_tags, pushed, should_pass in cases:
    rc, out, written = run_signref(version, channel, guard_tags, pushed)
    if should_pass:
        check(f"signref: {desc}", rc == 0 and f"digest={DIGEST}" in written and f"repo={IMG}" in written, out)
    else:
        check(f"signref: {desc}", rc != 0 and "digest=" not in written, out)

# ── the GitHub Release flags, exactly as the workflow computes them ───────────────────
release = step_block("Create the GitHub Release")
m = re.search(r"\n(\s*case \"\$\{CHANNEL\}:\$\{LATEST\}:\$\{VERSION\}\" in\n.*?\n\s*esac)\n", release, re.S)
CASE = textwrap.dedent(m.group(1)) if m else ""
check("github-release step decides flags from CHANNEL, LATEST and VERSION", bool(CASE))
for var in ("CHANNEL", "LATEST"):
    check(f"github-release step env passes {var}", re.search(rf"^\s+{var}: \$\{{\{{ needs\.version\.outputs\.", release, re.M) is not None)


def flags(channel, latest, version):
    script = "set -euo pipefail\nflags=()\n" + CASE + "\nprintf '%s\\n' \"${flags[@]}\"\n"
    env = dict(os.environ, CHANNEL=channel, LATEST=latest, VERSION=version)
    r = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True)
    return r.returncode, r.stdout.split()


for desc, args, want in [
    ("beta -> prerelease, not latest", ("beta", "false", "0.3.0-beta.1"), ["--prerelease", "--latest=false"]),
    ("stable newest line -> full release marked Latest", ("stable", "true", "0.3.0"), ["--latest"]),
    ("stable older line -> full release, not Latest", ("stable", "false", "0.2.4"), ["--latest=false"]),
]:
    rc, got = flags(*args)
    check(f"release flags: {desc}", rc == 0 and got == want, f"rc={rc} got={got}")
for desc, args in [
    ("beta marked latest is refused", ("beta", "true", "0.3.0-beta.1")),
    ("beta channel with a final version is refused", ("beta", "false", "0.3.0")),
    ("stable channel with a prerelease version is refused", ("stable", "true", "0.3.0-beta.1")),
    ("no channel is refused", ("none", "false", "0.3.0")),
    ("empty channel is refused", ("", "", "0.3.0")),
]:
    rc, got = flags(*args)
    check(f"release flags: {desc}", rc != 0, f"rc={rc} got={got}")

# ── triggers, checkout depth, overwrite guard ─────────────────────────────────────────
check("push runs on main and release/**", re.search(r"^\s+branches: \[main, 'release/\*\*'\]$", WF, re.M) is not None)
check("tag pushes still run on v*", re.search(r"^\s+tags: \['v\*'\]$", WF, re.M) is not None)
check("no pull_request trigger", re.search(r"^\s+pull_request(_target)?:", WF, re.M) is None)
version_job = WF.split("\n  version:\n", 1)[1].split("\n  image:\n", 1)[0]
check("version job checks out with fetch-depth: 0", re.search(r"^\s+fetch-depth: 0$", version_job, re.M) is not None)
check("version job runs the guard tests and the guard",
      "bash scripts/test-release-version.sh" in version_job and "bash scripts/release-version.sh" in version_job)
for out in ("channel", "latest"):
    check(f"version job exports {out}", f"{out}: ${{{{ steps.guard.outputs.{out} }}}}" in version_job)
overwrite = step_block("Refuse to overwrite a published version")
check("overwrite guard inspects only the immutable :<version>",
      'ref="${IMAGE}:${VERSION}"' in overwrite and "docker buildx imagetools inspect" in overwrite
      and not re.search(r":(latest|beta)\b", "\n".join(
          l for l in overwrite.split("run: |", 1)[1].splitlines() if not l.lstrip().startswith("#"))))

if FAILURES:
    print(f"\ntest-release-workflow: {FAILURES} failure(s)", file=sys.stderr)
    sys.exit(1)
print("\ntest-release-workflow: all checks passed")
