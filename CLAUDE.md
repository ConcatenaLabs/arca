# Working on Arca

Notes for AI coding agents and new contributors: the conventions that are not
obvious from the code. `AGENTS.md` is a link to this file. [README.md](README.md)
says what Arca is and how the workspace is laid out; read it first.

<!-- BEGIN SHARED AGENT CONVENTIONS: identical in every Sequentia repo. Change it in all of them together. -->
## Working with git and GitHub here

These rules are the same in every Sequentia repository. They are repeated in each
one because this file is the only thing an agent is guaranteed to read, whatever
machine it is working from.

**Nothing pushed to GitHub credits Claude, Anthropic, or any AI tool.** No
`Co-Authored-By: Claude` trailer, no `Claude-Session:` trailer or `claude.ai`
link, no "Generated with Claude Code" in a commit message or a pull request body,
no `claude/*` branch names or session ids, and no mention in source, comments,
docs or issue text. Agent tooling offers several of these by default; compose the
message without them rather than stripping them afterwards.

**Author every commit as the person the session is working for.** Several people
commit in these repositories and an agent always runs on behalf of one of them,
so derive the author from the authenticated GitHub account rather than from a
list of names that goes stale the moment somebody new arrives:

    git -c user.name="$(gh api user --jq '.name // .login')" \
        -c user.email="$(gh api user --jq '"\(.id)+\(.login)@users.noreply.github.com"')" \
        commit ...

That address is the GitHub `noreply` form, which is what links a commit to its
account and keeps private addresses out of a public history. When `gh` is not
authenticated as the person the work belongs to, ask them instead of guessing.

**Never infer the author from `git log`.** The clones carry no `user.name` or
`user.email`, so `git commit` stops with "Author identity unknown" and the
nearest answer to hand is the author of the last commit — which is whoever
pushed last and says nothing about who is working now. Attributing a commit to
someone who did not write it puts their name on code they never reviewed, and
taking it back costs a history rewrite and a force-push over commits other
machines have already pulled.

**Every change lands through a pull request that you merge yourself, at once.**
There is no reviewer on this project; the pull request exists so the reasoning is
recorded beside the diff. Branch, push, open it, merge it, delete the branch, all
in one sitting. Pushing straight to the default branch is the rule most often
broken here, and it is the one that costs the record. A pull request stays open
only when the repository owner asks for that specific one, and that never carries
over to the next.

**Name branches `area/short-description`**: `fix/`, `doc/`, `feature/`, `test/`,
`build/`, or the component being changed. Never a tool name, a session id, or
`worktree-*`.

**Write the subject as `area: what changed`**, one line, 72 characters at the
outside and 50 where you can manage it. Put the reasoning in the body, and
explain why rather than what.

**These repositories are public and world-readable.** Never commit private keys,
seeds, `wallet.dat`, RPC credentials, `.env` files or API tokens. Read the diff
before every commit. Secrets belong on the server and in offline backups.

**A file belongs to the repository whose code it describes.** Decide which repo
owns it before writing it; if it landed in the wrong one, move it rather than
deleting it.

**Documentation is part of the change, not a follow-up.** A change that makes a
README, a doc page, a runbook or a code comment wrong is not finished until that
text is right again, in the same pull request as the code. Before you open the
pull request, search the repository for whatever you renamed, moved or removed —
the old binary name, the old path, the old flag, the old command — and fix every
hit. If the change falsifies another repository's documentation, that repository
gets its own pull request in the same sitting. A stale instruction costs a new
user more than a missing one: they trust it, run it, it fails, and the failure
reads as broken software rather than as an out-of-date sentence.

**Write documentation to be timeless.** Assume the reader is new, arrived today,
and wants to know what the software is and how to use it right now. They do not
care what changed, what it used to be called, or which version added what. So
write in the present tense about current behaviour, and leave the history out:
no changelogs, no "new in", no "recently", no "coming soon", no status or
progress sections, no roadmaps, no dated notes. Quote a version number only where
the reader cannot act without it, and prefer pointing at the file that carries it
over copying the digits. Timeless does not mean thin — what the product is, who
it is for, and how to install, configure and use it all still belong there, in
full. Documentation written this way survives a release without an edit, which is
what keeps it true; the history already has homes in the git log, the tags and
the release notes.

**Push the same day you commit.** The testnet server pulls only from GitHub, so a
branch left on one laptop is invisible to every other machine and to the box.
<!-- END SHARED AGENT CONVENTIONS -->

## This repository and upstream Bark

This repository is a fork of Bark (`https://gitlab.com/ark-bitcoin/bark`) at the
`0.7.1` release, with Bark's full history. Bark's other tags and its branches exist
only on GitLab; fetch them from there when you need them
(`git fetch https://gitlab.com/ark-bitcoin/bark.git 'refs/tags/*:refs/tags/*'`).

- Keep upstream recognisable: one commit per logical change, never squash or
  rewrite upstream history, and never push upstream's branches here.
- Upstream is a source of individually reviewed patches, not a branch to merge.
  Cherry-pick a fix with `git cherry-pick -x` so the commit names its origin.
- Bark's MIT licence and copyright line stay in `LICENSE`; ours sits beneath it.
- Never open merge requests, issues or comments on the upstream project from
  here. If a fix belongs upstream, prepare the branch and say so.

## Names

Package names carry the `arca-` prefix; directory names and library names are
Bark's (`lib/` is the package `arca-lib` whose library is `ark`). The library
names are what the sources `use`, so changing one rewrites every import in the
workspace and every patch taken from upstream. Rename a package, never a library.

`contrib/agents/` holds Bark's own notes for agents. Their code conventions apply
here (tabs, `CONTRIBUTING/STYLE.md`, `contrib/agents/skills/protocol-encoding.md`
and `writing-tests.md`); their workflow (GitLab pipelines, changelog entries, the
Nix shell as a precondition for writing code) does not.

## Building and testing

The full workspace is large. Build and test the crate you are changing
(`cargo test -p arca-lib --lib`), not `--workspace`, unless the change crosses
crates.

`arca-lib`'s unit tests verify every transaction they build with `bitcoinkernel`,
which compiles Bitcoin Core's kernel through CMake and needs Boost headers with a
CMake package config (`libboost-dev` on Debian and Ubuntu). On a machine without
it, a directory holding a `lib/cmake/Boost-<version>/BoostConfig.cmake` that
defines `Boost::headers`, named in `CMAKE_PREFIX_PATH`, is enough.

`arca-consensus` is the verifier for Sequentia transactions: it links the node's
consensus library from the checkout named by `SEQUENTIA_DIR`, and its agreement
test runs the node named by `SEQUENTIAD_EXEC` (`consensus/README.md`). A unit test
that builds a Sequentia transaction ends by verifying it there. A negative case
that matters is also forced into a block on a regtest node (`generateblock`), not
only refused by the mempool, because relay policy can hide a consensus flaw.

Sequentia's transaction and block types come from `arca-sequentia-ext`, which
re-exports the `rust-elements` SWK vendors with its `sequentia` feature (pinned
once in the root `Cargo.toml`). Do not add another copy of that patch, and do not
depend on upstream `elements` directly: its encoding of issuances and headers is
not Sequentia's. Tests that need a node start one with
`sequentia_ext::regtest::Regtest`, which anchors the chain to a Bitcoin regtest
parent.

`arca-covenant` (`covenant/`) builds every Arca script, its witnesses and the
client's checks on a round, and holds the leaf record and its validation, the
tree builder and the unroll; it is where new script code goes. It depends on `elements`, `thiserror` and, for the
record's JSON form, `serde` and `serde_json`, so a wallet can use it without
`arca-lib`. The Sequentia Wallet Kit builds it with the Rust it pins, so the
crate uses no standard-library API newer than its `rust-version` (1.85, in
`covenant/Cargo.toml`), which the `covenant` workflow checks. Bark's MuSig2
policies in `arca-lib` stay until a later package removes them.

`regtest/` is the independent reference for every Arca script: a Python suite
on the node's functional test framework, and the golden vectors it exports
(`regtest/README.md`). Rust code that builds an Arca script must reproduce the
vector byte for byte. A script change starts there: change the builder in
`regtest/arklib3.py`, run the suite, regenerate the vectors with
`regtest/vectors.py`, and commit the result with the Rust change. CI fails when
the vectors no longer regenerate byte for byte. The leaf record's format is
held the same way: `regtest/records.py` states it and writes
`regtest/vectors/records.json`, and a change to the record changes both.

CI runs on GitHub Actions (`.github/workflows/`). Check it after every merge.

## Rules from Sequentia that bind this code

Arca runs on Sequentia, and the chain's design rules apply to every line here:

- **Bitcoin anchoring is supreme.** Sequentia reorgs whenever its Bitcoin anchor
  does, with no depth limit. Nothing here may resist that. A transaction is final
  only when its block is certified and that block's anchor is buried.
- **Time-based locks.** Expiry and exit delays are median-time locks, not block
  counts: a height-based expiry slips after an anchor rollback.
- **No privileged asset.** Every asset can have batches. Fees are paid in an
  accepted asset, default to the asset being moved, and never fall back to the
  Sequence token (SEQ). Fee rates are in the fee asset's own units per vbyte,
  never "sat/vB". Never assume an asset stays accepted for fees.
- **Transparent by default.** Outputs are explicit; confidentiality is the
  holder's choice per transfer. Code that only works on the confidential path is
  a bug.
- **Native BTC, not pegged.** Bitcoin on Sequentia is native bitcoin on the parent
  chain; SBTC is a narrow opt-in. Wallets built on this code are dual-chain.
- **Names.** The network is Sequentia; the token is the Sequence token (SEQ). An
  exchange on it is disintermediated, never "decentralized".
- **Arca stays off public web pages.** This repository and its README are public;
  no public site copy names or links Arca.
