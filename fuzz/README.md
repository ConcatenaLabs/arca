# Bark Fuzzing

We use [honggfuzz](https://github.com/google/honggfuzz) with
[cargo-hfuzz](https://crates.io/crates/honggfuzz) to fuzz Bark's codebase.
The primary goal is to find inputs that cause panics, assertion failures, or
inconsistencies in VTXO encoding, preventing denial-of-service vulnerabilities
where malformed client data crashes the server.

## Prerequisites

### Using Nix (recommended)

All required dependencies (including `honggfuzz`, `binutils`, `libunwind`,
`gdb`, etc.) are provided by the project's Nix flake. Enter the dev shell
from the `bark/` root:

```bash
nix develop --extra-experimental-features "flakes nix-command"
```

> **Note:** The Nix package provides the `honggfuzz` binary but *not* the
> `cargo hfuzz` subcommand. The `fuzz.sh` script handles installing
> `cargo-hfuzz` automatically on first run.

### Platform support

Honggfuzz only runs on **Linux**. It does not work on macOS. If you are using
MacOS, the recommended workflow is to develop locally on macOS and run fuzzing
on a Linux server.

### glibc 2.40 workaround

On systems with glibc 2.40+, honggfuzz conflicts with `_FORTIFY_SOURCE`.
The `fuzz.sh` script applies the workaround automatically. If running
`cargo hfuzz` manually, prefix your command with:

```bash
NIX_HARDENING_ENABLE="" CFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 $CFLAGS" cargo hfuzz run <target>
```

## Project structure

```bash
fuzz/
├── src/bin/            # Fuzz target source files
│   ├── vtxo_decode.rs
│   └── other targets go here
├── hfuzz_workspace/    # Honggfuzz runtime data & crash files
├── hfuzz_input/        # Optional seed corpora (per-target)
├── fuzz.sh             # Fuzzing orchestration script
├── debug.sh            # Crash analysis & debugging script
├── Cargo.toml
└── README.md
```

## Fuzzing targets

To help with fuzzing the targets, we crafted a `fuzz.sh` script to check the
needed dependencies and run each target sequentially by default, while allowing
arguments to be passed to costumize the control on fuzzing.

To run a single target:

```bash
./fuzz.sh <TARGET>
```

Run all targets sequentially (1 hour each by default):

```bash
./fuzz.sh
```

To check for possible arguments and usage:

```bash
./fuzz.sh --help
```

### Input corpus

If a directory `hfuzz_input/<target>/` exists, honggfuzz will use it as a
seed corpus. Adding real serialized VTXOs or other valid inputs here
significantly improves fuzzing effectiveness by giving the fuzzer a head
start toward interesting code paths. We currently hold a fuzz corpus on
our [bark-qa repo](https://gitlab.com/ark-bitcoin/bark-qa). Use the helper
script in it to pull the inputs to start fuzzing from a better corpus.

To run using the existing corpus, clone [bark-qa](https://gitlab.com/ark-bitcoin/bark-qa)
and run:

```bash
./fuzz.sh <target> --use-corpus <path_to_cloned_bark_qa>
```

Or combine it with other flags:

```bash
~/bark/fuzz$ ./fuzz.sh --use-corpus ~/../bark-qa -t 5000
```

### The covenant targets

`covenant_policy_decode`, `covenant_witness_parse`, `covenant_round_check`,
`covenant_record_decode`, `covenant_record_json`, `covenant_coin_record_decode`
and `covenant_board_record` fuzz `arca-covenant`: the decoders of every policy
and of the clock schedule (what decodes must re-encode to the same bytes and
build its scripts), the readers of witnesses found on-chain, the five client
checks on an arbitrary round transaction, the leaf record's binary and JSON
readers (what decodes must read the same from both forms and rebuild its path),
the coin record a receiver gets for an out-of-round transfer (what decodes must
re-encode to the same bytes and go through validation without a panic), and the
board record's two forms. Their bodies are in `src/covenant.rs`.

The same bodies also run under libFuzzer on a stable toolchain, without
honggfuzz. The driver, `libfuzzer/covenant.rs`, picks a body by the first byte
and treats any panic as a crash; with `ARCA_FUZZ_BODY` set to `policy`, `witness`,
`round`, `record`, `record_json`, `coin` or `board` it gives every input to
that body whole. Build it with coverage
instrumentation for the
host target (so the flags do not reach build scripts), then run it:

```bash
RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares" \
  cargo build --manifest-path fuzz/Cargo.toml --release --features libfuzzer \
  --bin covenant_libfuzzer --target x86_64-unknown-linux-gnu
mkdir -p fuzz/corpus
fuzz/target/x86_64-unknown-linux-gnu/release/covenant_libfuzzer fuzz/corpus -max_total_time=600 -max_len=4096
```

A seed corpus helps it reach deep paths quickly: encodings of real policies
prefixed with `0x00`, witness stacks (each item as one length byte and the item)
prefixed with `0x01`, serialised transactions prefixed with `0x02`, leaf records
prefixed with `0x03` and their JSON texts with `0x04`, coin records prefixed with
`0x05`, board records (either form) with `0x06`; the golden vectors
(`regtest/vectors/arca.json`, `records.json` and `transactions.json`) hold all
seven.

## Debugging crashes

When honggfuzz finds a crash, it saves the triggering input under
`hfuzz_workspace/<target>/` with a filename like
`SIGABRT.PC.7fff....INSTR.mov____%eax,%ebp.fuzz`.

Use the debug script to analyze crashes:

```bash
./debug.sh <TARGET>
```

This will list available crash files, let you select one, and launch GDB
with the correct environment. Inside GDB, use `run` to reproduce the crash
and `bt` to get a backtrace.

To check available options:

```bash
./debug.sh --help
```

## Creating new fuzz targets

1. Duplicate an existing file in `fuzz/src/bin/`, e.g. `vtxo_decode.rs`,
   and rename it to match your new target (say `loud_barking.rs`).

2. In the new file, update the imports and modify the `do_test` function
   body to exercise the functionality you want to fuzz. Keep the function
   signature unchanged.

3. If your target depends on a crate not already listed in
   `fuzz/Cargo.toml`, add it as a dependency.

4. Verify the new target compiles (remember to check the needed dependencies
and use `./fuzz.sh` as needed):

   ```bash
   cargo hfuzz build
   ```

5. Run it:

   ```bash
   ./fuzz.sh loud_barking
   ```
