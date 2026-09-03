# Releasing

Publishing to PyPI is automated by [.github/workflows/release.yml](.github/workflows/release.yml). This document covers the one-time setup it needs and how the flow works day to day.

## One-time setup (do this before the first automated release)

1. **Create a PyPI API token** and add it to this repo as a GitHub Actions secret named `PYPI_API_TOKEN`.
   - `autopyara` has not been published yet, so the token must be scoped to your **entire PyPI account** (an existing-project-scoped token isn't possible until after the first upload). Once the first release lands, you can go back and re-scope/replace it with a project-scoped token for `autopyara` if you'd rather not keep an account-wide token around.
   - Add it at: repo **Settings → Secrets and variables → Actions → New repository secret**, name `PYPI_API_TOKEN`.
2. **Create `RELEASE_PAT`** (a fine-grained Personal Access Token) and **set up the branch protection ruleset** described below. Skipping this either leaves `main` open to direct pushes from anyone with write access, or (if you protect `main` without the PAT/bypass setup) breaks the `release` job's version-bump push.
3. That's it — no PyPI "trusted publisher" registration is needed since this uses a token, not OIDC.

## Branch protection: PRs required, except for the release bot

Goal: nobody — not outside contributors, not org members — pushes directly to `main`. The one deliberate exception is the release automation's version-bump commit, which must keep working.

**There is no "GitHub Actions app" bypass option** — GitHub Ruleset bypass lists here are role-based (Organization admin, Repository admin, Maintain, Write, Deploy keys, plus a couple of special actors like Copilot's coding agent and the GitHub Merge Queue). The default `GITHUB_TOKEN` a workflow runs with doesn't hold any of those roles, so it can't be bypassed by name. The actual mechanism: authenticate the release push with a **Personal Access Token belonging to an account that holds a bypassable role**, and put that role in the bypass list.

1. **Create the PAT**: your account's **Settings → Developer settings → Personal access tokens → Fine-grained tokens → Generate new token**.
   - Resource owner: `Botacin-s-Lab`
   - Repository access: only `AutoPYaraPyPI`
   - Repository permissions: **Contents: Read and write**
   - Pick an expiration (e.g. 1 year) — you'll need to regenerate and update the secret before it expires.
2. **Add it as a repo secret** named `RELEASE_PAT` (same place as `PYPI_API_TOKEN`).
3. Go to the repo's **Settings → Rules → Rulesets → New ruleset → New branch ruleset**.
4. **Enforcement status:** Active.
5. **Target branches:** Include default branch (`main`).
6. **Bypass list:** add **Repository admin** — the role your PAT's account holds. Do not add any human accounts/teams beyond that role — the point is that humans still go through a PR; only a push authenticated as a repo admin (which is what `RELEASE_PAT` gives the `release` job) bypasses.
7. Enable these rules:
   - **Require a pull request before merging**, with **required approvals: 1**.
   - **Require status checks to pass** — add the check(s) produced by [.github/workflows/pr-checks.yml](.github/workflows/pr-checks.yml) (job `test`, matrixed across Python 3.9–3.12, so you'll see one check per version, e.g. `test / test (3.9)`). Note: a status check only becomes selectable in this UI after it has run at least once — open one throwaway PR first if the list is empty.
   - **Block force pushes** and **Restrict deletions** (standard hygiene, not strictly required by anything above).

With this in place: an outside contributor forks the repo, pushes to their fork, and opens a PR against `main` — [pr-checks.yml](.github/workflows/pr-checks.yml) runs the full build+install+test suite on it automatically (no secrets exposed to fork PRs — it runs on plain `pull_request`, which GitHub gives a read-only token for forks regardless of what the workflow requests). Once a maintainer approves and the checks are green, merging is allowed. The `release` job's checkout step authenticates with `RELEASE_PAT` (see `release.yml`), so its direct push to `main` still lands despite the required-PR rule.

## How a release happens

1. Make whatever code changes you want on `main` as normal — via a PR, per the branch protection above.
2. When you're ready to cut a release, the commit that actually lands on `main` needs a **subject line** (first line only — the body doesn't count) containing one of two trigger phrases:
   - **"New subversion"** → **patch** bump, e.g. `0.1.5` → `0.1.6`
   - **"New version"** → **minor** bump, e.g. `0.1.5` → `0.2.0` (patch resets to `0`)

   Both phrases are case-insensitive. Only the subject line is checked — never put either phrase in a commit body describing this process, or you'll retrigger a release accidentally (this has already happened once; see the git history around the `release.yml` self-match fix).

   **Merge strategy matters here now that `main` requires PRs.** The commit GitHub actually pushes to `main` on merge depends on which merge button you use:
   - **Squash and merge** / **Create a merge commit** — GitHub generates a *new* commit message (e.g. "Merge pull request #N ...") by default. You must manually edit that title in the merge confirmation box to read one of the trigger phrases before confirming, or nothing fires.
   - **Rebase and merge** — replays your original commit(s) as-is, so if your commit's subject already says "New subversion"/"New version", it survives onto `main` unchanged and fires correctly.

   If you forget this and merge without checking, the merge just won't trigger a release — nothing breaks, but nothing publishes either. Re-check by looking at the actual commit that landed on `main` (`git log -1 origin/main`) if a release doesn't seem to have fired when you expected one.
3. GitHub Actions then runs, in order:
   - **`gate`** — checks the head commit's subject line for either phrase and decides `patch` vs `minor`. Everything below only runs if one matched.
   - **`test`** — across Python 3.9–3.12: builds the sdist + wheel, installs the wheel (the same artifact a real `pip install autopyara` would fetch), restores/downloads the bloom filter data, and runs the full test suite (`tests/`) — including `tests/test_smoke_generate.py`, which runs the real pipeline end-to-end against a real JVM. This is the actual "does this release work" check; a failure here stops the release and nothing gets published, regardless of which trigger phrase was used.
   - **`release`** (only if `test` passed on every Python version) — bumps `setup.py`'s version per the `gate` job's decision, commits that as `Release vX.Y.Z [automated]`, tags it `vX.Y.Z`, pushes both to `main`, builds the sdist + wheel from the bumped code, runs `twine check`, uploads both to PyPI, and creates a GitHub Release with both attached and auto-generated notes.

You never need to hand-edit the version number yourself — the trigger phrase you use decides the bump. If you need a major bump instead, edit `version="X.Y.Z"` in [setup.py](setup.py) yourself in a **separate, prior** commit (one whose subject contains neither trigger phrase), then make your actual trigger commit — the automated bump always increments whatever is currently in `setup.py`.

## Where the Java requirement is checked

AutoPYara needs a JRE (11+) to actually run (its backend is a JVM process — see `autopyara/interface.py`'s `PythonInterface._check_java_installed()`, which raises a clear error the first time `AutoPYara()` is constructed without one). That check deliberately does **not** run at `pip install` time — `setup.py` has no Java gate, and the package ships both a wheel and an sdist, so most installs never execute `setup.py` at all. Blocking install on Java would be inconsistent (wheel installs would bypass it anyway) and would get in the way of installing the package somewhere it'll only run later (e.g. building a Docker image on a Java-less host).

Instead, real functional correctness — a full JVM run against the exact wheel that's about to be published — is what `tests/test_smoke_generate.py` verifies in the `test` job, before `release` is ever allowed to run. That's the actual pre-publish gate.

## Where the bloom filter data comes from

`autopyara/data/blooms/` (~600MB, gitignored, not shipped in the sdist) is fetched at first `import autopyara` — or on demand via the `autopyara-download` console script — from the [`data-branch`](https://github.com/Botacin-s-Lab/AutoPYaraPyPI/tree/data-branch) branch of this same repository (see [autopyara/download.py](autopyara/download.py)). To update the shipped bloom filters, push new data to `data-branch` in the same `data/blooms/{ember,autopyara}/{benign,malicious}/*.bloom` layout — no code change needed, and no version bump is required for the data itself to change (existing installs re-download whenever their local `autopyara/data/blooms` directory is missing).
