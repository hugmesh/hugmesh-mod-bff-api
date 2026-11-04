#!/usr/bin/env python3
"""Tests for .github/workflows/release.yml. Runs the workflow's own steps, extracted from the
file: the signref check and the Release flags against each channel, and the overwrite guard,
the floating-tag re-check, the digest check and the GitHub Release under bash -e, the way GitHub
runs them, with docker and gh stubbed and a throwaway git origin. Standard library only (no
PyYAML), no network. Run: python3 scripts/test-release-workflow.py
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

# ── the shell steps, run the way GitHub runs them ─────────────────────────────────────
# A step with no shell: key runs as `bash -e {0}`, and `set -uo pipefail` does not turn -e off.
check("release.yml sets no shell/defaults (these tests assume GitHub's bash -e {0})",
      re.search(r"^\s*(defaults|shell):", WF, re.M) is None)


def run_body(step_name):
    """The run: block of the step called step_name, dedented."""
    lines = step_block(f"- name: {step_name}").splitlines()
    for i, line in enumerate(lines):
        if re.fullmatch(r"\s*run: \|", line):
            indent = len(line) - len(line.lstrip())
            body = []
            for raw in lines[i + 1:]:
                if raw.strip() and len(raw) - len(raw.lstrip()) <= indent:
                    break
                body.append(raw)
            return textwrap.dedent("\n".join(body)) + "\n"
    raise SystemExit(f"step {step_name!r} has no run: block")


TMP = tempfile.TemporaryDirectory()
WORK = TMP.name
BIN = os.path.join(WORK, "bin")
os.makedirs(BIN)
LOG = os.path.join(WORK, "stub.log")


def stub(name, script):
    path = os.path.join(BIN, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(script)
    os.chmod(path, 0o755)


def run_step(step_name, env, cwd=WORK):
    """Runs the step under bash -e; returns (rc, combined output, lines the stubs logged)."""
    path = os.path.join(WORK, "step.sh")
    with open(path, "w", encoding="utf-8") as f:
        f.write(run_body(step_name))
    open(LOG, "w").close()
    full = {k: v for k, v in os.environ.items() if not k.startswith(("GITHUB_", "RELEASE_"))}
    full.update({"PATH": BIN + os.pathsep + os.environ["PATH"], "IMAGE": IMG, "STUB_LOG": LOG})
    full.update(env)
    r = subprocess.run(["bash", "--noprofile", "--norc", "-e", path], cwd=cwd, env=full, capture_output=True, text=True)
    return r.returncode, r.stdout + r.stderr, open(LOG).read().splitlines()


# Behaves like real buildx v0.31.0: `inspect REF` alone, and any format that starts with
# {{.Manifest, print the listing; {{json .Manifest.Digest}} prints the digest in quotes. STUB_REGISTRY
# maps ref to digest, or to an error text. The overwrite guard and the digest check share it.
stub("docker", r"""#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as log:
    log.write(" ".join(a) + "\n")
if a[:3] != ["buildx", "imagetools", "inspect"] or len(a) not in (4, 6) or (len(a) == 6 and a[4] != "--format"):
    sys.exit(f"stub docker: unexpected args {a}")
ref = a[3]
fmt = a[5] if len(a) == 6 else ""
got = json.loads(os.environ["STUB_REGISTRY"]).get(ref, "ERROR: " + ref + ": not found")
if got.startswith("ERROR"):
    print(got, file=sys.stderr)
    sys.exit(1)
if fmt == "{{json .Manifest.Digest}}":
    print('"' + got + '"')
elif fmt == "" or fmt.startswith("{{.Manifest"):
    print(f"Name:      {ref}\nMediaType: application/vnd.oci.image.index.v1+json\nDigest:    {got}\n")
else:
    sys.exit(f"stub docker: unexpected format {fmt}")
""")


# 1. "Refuse to overwrite a published version"
def overwrite_step(channel, version, registry):
    return run_step("Refuse to overwrite a published version",
                    {"VERSION": version, "CHANNEL": channel, "STUB_REGISTRY": json.dumps(registry)})


for channel, version in [("beta", "0.3.0-beta.1"), ("stable", "0.3.0")]:
    ref = f"{IMG}:{version}"
    for desc, answer in [("not found", None),
                         ("MANIFEST_UNKNOWN", "ERROR: failed to authorize: MANIFEST_UNKNOWN: manifest unknown"),
                         ("name unknown", "ERROR: name unknown")]:
        rc, out, calls = overwrite_step(channel, version, {} if answer is None else {ref: answer})
        check(f"overwrite step, {channel}: {desc} on a first publish continues under bash -e",
              rc == 0 and "is not published yet; continuing" in out and calls == [f"buildx imagetools inspect {ref}"],
              f"rc={rc} calls={calls} out={out}")
    rc, out, _ = overwrite_step(channel, version, {ref: DIGEST})
    want = "fix forward" if channel == "stable" else "raise the -beta.N"
    check(f"overwrite step, {channel}: a published version is refused with the {channel} message",
          rc != 0 and "already exists in GHCR" in out and want in out and "continuing" not in out, f"rc={rc} out={out}")
    rc, out, _ = overwrite_step(channel, version, {ref: "ERROR: failed to authorize: denied: denied"})
    check(f"overwrite step, {channel}: an unclassified registry answer fails closed",
          rc != 0 and "could not tell whether" in out and "denied" in out and "continuing" not in out, f"rc={rc} out={out}")
rc, out, calls = overwrite_step("stable", "0.3.0", {f"{IMG}:latest": DIGEST, f"{IMG}:0.3": DIGEST})
check("overwrite step: floating :X.Y and :latest existing do not stop a stable",
      rc == 0 and calls == [f"buildx imagetools inspect {IMG}:0.3.0"], f"rc={rc} calls={calls} out={out}")

# 2. "Check every pushed tag resolves to the signed digest"
OTHER = "sha256:" + "b" * 64
PUSHED = [f"{IMG}:0.3.0", f"{IMG}:sha-0123456789ab", f"{IMG}:0.3", f"{IMG}:latest"]


def digest_step(tags, registry):
    return run_step("Check every pushed tag resolves to the signed digest",
                    {"TAGS": ",".join(tags), "DIGEST": DIGEST, "STUB_REGISTRY": json.dumps(registry)})


rc, out, calls = digest_step(PUSHED, {t: DIGEST for t in PUSHED})
check("digest step: every tag on the signed digest passes, and each tag was asked",
      rc == 0 and [c.split()[3] for c in calls] == PUSHED, f"rc={rc} calls={calls} out={out}")
rc, out, _ = digest_step(PUSHED, dict({t: DIGEST for t in PUSHED}, **{f"{IMG}:latest": OTHER}))
check("digest step: a tag on another digest is refused and named",
      rc != 0 and f"{IMG}:latest resolves to {OTHER}" in out, f"rc={rc} out={out}")
rc, out, _ = digest_step(PUSHED, {t: DIGEST for t in PUSHED[:-1]})
check("digest step: a pushed tag the registry cannot find is refused", rc != 0, f"rc={rc} out={out}")
rc, out, calls = digest_step([], {})
check("digest step: no tags at all is refused, not a vacuous pass", rc != 0 and not calls, f"rc={rc} calls={calls} out={out}")

# ── a real origin and checkout, for the two steps that ask the version guard again ────
#   M ── main (pom 0.4.0-beta.1)      R ── release/0.3 (pom 0.3.0)      O ── release/0.2 (pom 0.2.1)
ORIGIN = os.path.join(WORK, "origin.git")
DEV = os.path.join(WORK, "dev")
POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <artifactId>mod-bff</artifactId>
  <version>%s</version>
</project>
"""


def git(*args, cwd=None):
    r = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
                        "-c", "tag.gpgSign=false", "-c", "init.defaultBranch=main", *args],
                       cwd=cwd, capture_output=True, text=True)
    if r.returncode:
        raise SystemExit(f"git {args}: {r.stdout}{r.stderr}")
    return r.stdout.strip()


def commit_pom(version):
    with open(os.path.join(DEV, "pom.xml"), "w", encoding="utf-8") as f:
        f.write(POM % version)
    git("add", "-A", cwd=DEV)
    git("commit", "-q", "-m", version, cwd=DEV)
    return git("rev-parse", "HEAD", cwd=DEV)


git("init", "-q", "--bare", ORIGIN)
git("init", "-q", DEV)
git("remote", "add", "origin", ORIGIN, cwd=DEV)
os.makedirs(os.path.join(DEV, "scripts"))
with open(os.path.join(ROOT, "scripts", "release-version.sh"), encoding="utf-8") as src, \
        open(os.path.join(DEV, "scripts", "release-version.sh"), "w", encoding="utf-8") as dst:
    dst.write(src.read())
BASE = commit_pom("0.2.0-beta.1")
M = commit_pom("0.4.0-beta.1")
git("push", "-q", "origin", "HEAD:refs/heads/main", cwd=DEV)
git("checkout", "-q", "-b", "r03", BASE, cwd=DEV)
R = commit_pom("0.3.0")
git("push", "-q", "origin", "HEAD:refs/heads/release/0.3", cwd=DEV)
git("checkout", "-q", "-b", "r02", BASE, cwd=DEV)
O = commit_pom("0.2.1")
git("push", "-q", "origin", "HEAD:refs/heads/release/0.2", cwd=DEV)
TAG_COMMITS = {"v0.3.0": R, "v0.2.1": O, "v0.4.0-beta.1": M}
for tag_name, sha in TAG_COMMITS.items():
    git("tag", tag_name, sha, cwd=ORIGIN)
CLONES = 0


def checkout(sha):
    """What actions/checkout with fetch-depth: 0 leaves: every branch and tag, HEAD on sha."""
    global CLONES
    CLONES += 1
    ws = os.path.join(WORK, f"ws{CLONES}")
    git("clone", "-q", ORIGIN, ws)
    git("checkout", "-q", "--detach", sha, cwd=ws)
    return ws


def on_origin(*names, at=R):
    for name in names:
        git("tag", name, at, cwd=ORIGIN)


def off_origin(*names):
    for name in names:
        git("tag", "-d", name, cwd=ORIGIN)


def guard_env(tag_name):
    return {"GITHUB_REF": f"refs/tags/{tag_name}", "GITHUB_SHA": TAG_COMMITS[tag_name]}


def version_job(tag_name, ws):
    """The version job's answer: the real guard's output, as the workflow passes it on."""
    full = dict(os.environ, IMAGE=IMG, GITHUB_OUTPUT="", **guard_env(tag_name))
    r = subprocess.run(["bash", "scripts/release-version.sh"], cwd=ws, env=full, capture_output=True, text=True)
    if r.returncode:
        raise SystemExit(f"fixture: the guard refused {tag_name}: {r.stderr}")
    return dict(line.split("=", 1) for line in r.stdout.splitlines())


# 3. "Re-check the floating tags against origin"
RECHECK = "Re-check the floating tags against origin"


def recheck(tag_name, ws, answer):
    return run_step(RECHECK, dict(guard_env(tag_name), WANT_TAGS=answer["tags"], WANT_LATEST=answer["latest"]), cwd=ws)


ws = checkout(R)
answer = version_job("v0.3.0", ws)
check("fixture: the version job says v0.3.0 moves :0.3 and :latest",
      answer["latest"] == "true" and f"{IMG}:0.3," in answer["tags"] + ",", str(answer))
rc, out, _ = recheck("v0.3.0", ws, answer)
check("re-check: nothing changed on origin, the run continues", rc == 0 and "still correct" in out, f"rc={rc} out={out}")

rc, out, _ = recheck("v0.3.0", ws, dict(answer, latest="false"))
check("re-check: the right tags with a different latest answer stop the run", rc != 0 and "Re-run all jobs" in out, f"rc={rc} out={out}")
rc, out, _ = recheck("v0.3.0", ws, dict(answer, tags=answer["tags"].replace(f",{IMG}:latest", "")))
check("re-check: the same latest answer with different tags stops the run", rc != 0 and "Re-run all jobs" in out, f"rc={rc} out={out}")

on_origin("v0.4.0")
rc, out, _ = recheck("v0.3.0", ws, answer)
check("re-check: a newer stable line tagged since the version job stops a stale :latest",
      rc != 0 and "Re-run all jobs" in out and f"{IMG}:latest" in out and "still correct" not in out, f"rc={rc} out={out}")
rc, out, _ = recheck("v0.3.0", ws, version_job("v0.3.0", ws))
check("re-check: after 'Re-run all jobs' the same tag goes through without :latest",
      rc == 0 and "latest=false" in out and f"{IMG}:latest" not in out, f"rc={rc} out={out}")
off_origin("v0.4.0")
git("fetch", "-q", "--force", "--prune", "origin", "+refs/tags/*:refs/tags/*", cwd=ws)

on_origin("v0.3.1")
rc, out, _ = recheck("v0.3.0", ws, answer)
check("re-check: a higher patch tagged since the version job stops :X.Y moving backwards",
      rc != 0 and "would move backwards" in out and "refuses it now" in out, f"rc={rc} out={out}")
off_origin("v0.3.1")
git("fetch", "-q", "--force", "--prune", "origin", "+refs/tags/*:refs/tags/*", cwd=ws)

on_origin("v0.4.0")
git("fetch", "-q", "--force", "origin", "+refs/tags/*:refs/tags/*", cwd=ws)
stale_false = version_job("v0.3.0", ws)
off_origin("v0.4.0")
rc, out, _ = recheck("v0.3.0", ws, stale_false)
check("re-check: a tag deleted from origin since the version job counts too (the fetch prunes)",
      rc != 0 and "Re-run all jobs" in out and "latest=true" in out, f"rc={rc} out={out}")

ws = checkout(O)
answer = version_job("v0.2.1", ws)
check("fixture: the version job says the older-line v0.2.1 does not move :latest", answer["latest"] == "false", str(answer))
rc, out, _ = recheck("v0.2.1", ws, answer)
check("re-check: an older-line patch still goes through, without :latest", rc == 0, f"rc={rc} out={out}")

ws = checkout(M)
answer = version_job("v0.4.0-beta.1", ws)
on_origin("v0.5.0")
rc, out, _ = recheck("v0.4.0-beta.1", ws, answer)
check("re-check: a beta does not depend on the stable tags", rc == 0, f"rc={rc} out={out}")
off_origin("v0.5.0")

# 4. "Create the GitHub Release": gh stubbed, flags read back, the guard real.
stub("gh", r"""#!/usr/bin/env bash
printf '%s\n' "$*" >> "${STUB_LOG}"
if [ "$1 $2" = "release view" ]; then
  [ "${STUB_RELEASE_EXISTS:-}" = yes ]
  exit $?
fi
[ "$1 $2" = "release create" ] && exit 0
echo "stub gh: unexpected $*" >&2
exit 97
""")
RELEASE_STEP = "Create the GitHub Release (beta prerelease never latest; stable latest only on the newest line)"


def github_release(tag_name, channel, latest, *newer_tags, exists=""):
    """The job's checkout happens now, so it holds newer_tags; the image job's answer was `latest`."""
    on_origin(*newer_tags)
    ws = checkout(TAG_COMMITS[tag_name])
    off_origin(*newer_tags)
    rc, out, calls = run_step(RELEASE_STEP, dict(
        guard_env(tag_name), GH_TOKEN="x", VERSION=tag_name[1:], SHA12=TAG_COMMITS[tag_name][:12], CHANNEL=channel, LATEST=latest,
        GITHUB_REF_NAME=tag_name, GITHUB_REPOSITORY="hugmesh/hugmesh-mod-bff-api", STUB_RELEASE_EXISTS=exists), cwd=ws)
    created = [c for c in calls if c.startswith("release create")]
    return rc, out, created[0].split() if created else None


rc, out, made = github_release("v0.3.0", "stable", "true")
check("github-release: newest stable, nothing newer since: marked Latest",
      rc == 0 and made and "--latest" in made and "--latest=false" not in made, f"rc={rc} made={made} out={out}")
rc, out, made = github_release("v0.3.0", "stable", "true", "v0.4.0")
check("github-release: a newer line tagged since the image job: created, not marked Latest",
      rc == 0 and made and "--latest=false" in made and "--latest" not in made and "::warning::" in out, f"rc={rc} made={made} out={out}")
rc, out, made = github_release("v0.3.0", "stable", "true", "v0.3.1")
check("github-release: a higher patch tagged since (the guard refuses): created, not marked Latest, not a red run",
      rc == 0 and made and "--latest=false" in made and "--latest" not in made and "would move backwards" in out, f"rc={rc} made={made} out={out}")
rc, out, made = github_release("v0.2.1", "stable", "false")
check("github-release: older-line patch: a full release, not marked Latest",
      rc == 0 and made and "--latest=false" in made and "--prerelease" not in made, f"rc={rc} made={made} out={out}")
off_origin("v0.3.0")  # the guard alone would now call v0.2.1 the newest line
rc, out, made = github_release("v0.2.1", "stable", "false")
on_origin("v0.3.0")
check("github-release: the fresh answer never marks Latest a release whose image did not move :latest",
      rc == 0 and made and "--latest=false" in made and "--latest" not in made, f"rc={rc} made={made} out={out}")
rc, out, made = github_release("v0.4.0-beta.1", "beta", "false")
check("github-release: beta: prerelease, not latest",
      rc == 0 and made and "--prerelease" in made and "--latest=false" in made, f"rc={rc} made={made} out={out}")
rc, out, made = github_release("v0.3.0", "stable", "true", exists="yes")
check("github-release: an existing Release is left alone", rc == 0 and made is None and "not touching it" in out, f"rc={rc} made={made} out={out}")

# 5. the wiring those steps depend on
image_job = WF.split("\n  image:\n", 1)[1].split("\n  github-release:\n", 1)[0]
release_job = WF.split("\n  github-release:\n", 1)[1].split("\n  notify-site:\n", 1)[0]
check("image job checks out with fetch-depth: 0", re.search(r"uses: actions/checkout@v4\n\s+with:\n\s+fetch-depth: 0\n", image_job) is not None)
check("github-release checks out with fetch-depth: 0, leaving no write token in the checkout",
      re.search(r"uses: actions/checkout@v4\n\s+with:\n\s+fetch-depth: 0\n\s+persist-credentials: false\n", release_job) is not None)
names = re.findall(r"^\s+- name: (.*)$", image_job, re.M)
check("the re-check is the last step before the build",
      names.index(RECHECK) + 1 == names.index("Build and push image"), str(names))
recheck_block = step_block(f"- name: {RECHECK}")
check("the re-check runs on every release run", "if: needs.version.outputs.kind == 'release'" in recheck_block)
for var in ("WANT_TAGS", "WANT_LATEST"):
    check(f"the re-check compares against the version job's {var}", re.search(rf"^\s+{var}: \$\{{\{{ needs\.version\.outputs\.", recheck_block, re.M) is not None)
check("the image is pushed with the tags the re-check just confirmed", "tags: ${{ needs.version.outputs.tags }}" in step_block("- name: Build and push image"))
digest_block = step_block("- name: Check every pushed tag resolves to the signed digest")
check("the digest check runs whenever signref succeeded, against the signed digest",
      "if: steps.signref.outcome == 'success'" in digest_block and "DIGEST: ${{ steps.signref.outputs.digest }}" in digest_block
      and "TAGS: ${{ needs.version.outputs.tags }}" in digest_block)
check("the digest check runs after the signature and both attestations",
      names.index("Attest the SBOM (pushed to the registry)") < names.index("Check every pushed tag resolves to the signed digest"), str(names))

if FAILURES:
    print(f"\ntest-release-workflow: {FAILURES} failure(s)", file=sys.stderr)
    sys.exit(1)
print("\ntest-release-workflow: all checks passed")
