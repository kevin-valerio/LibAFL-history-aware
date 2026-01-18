# `LibAFL-history-aware` (a `LibAFL` fork)

 <img align="right" src="https://raw.githubusercontent.com/AFLplusplus/Website/main/static/libafl_logo.svg" alt="LibAFL logo" width="250" heigh="250">

Advanced Fuzzing Library - Slot your own fuzzers together and extend their features using Rust.

This repository is a fork of [`AFLplusplus/LibAFL`](https://github.com/AFLplusplus/LibAFL) focused on **history-aware scheduling**:
it keeps classic coverage-guided fuzzing, but additionally biases corpus scheduling toward inputs that execute **recently changed code**, based on `git blame`.

`LibAFL` is a collection of reusable pieces of fuzzers, written in Rust, it gives you many of the benefits of an off-the-shelf fuzzer, while being completely customizable.
Some highlight features currently include:

- `fast`: We do everything we can at compile time, keeping runtime overhead minimal. Users reach 120k execs/sec in frida-mode on a phone (using all cores).
- `scalable`: `Low Level Message Passing`, `LLMP` for short, allows `LibAFL` to scale almost linearly over cores, and via TCP to multiple machines.
- `adaptable`: You can replace each part of `LibAFL`. For example, `BytesInput` is just one potential form input:
feel free to add an AST-based input for structured fuzzing, and more.
- `multi platform`: `LibAFL` runs on *Windows*, *macOS*, *iOS*, *Linux*, and *Android*, and more. `LibAFL` can be built in `no_std` mode to inject `LibAFL` into obscure targets like embedded devices and hypervisors.
- `bring your own target`: We support binary-only modes, like Frida-Mode, as well as multiple compilation passes for sourced-based instrumentation. Of course it's easy to add custom instrumentation backends.

## This fork: Git-aware / recently-changed coverage scheduling

### What it does

- Keeps coverage-guided fuzzing unchanged by default.
- Adds an **opt-in scheduling bias** that prefers testcases that execute code that was **recently modified or added**.
- “Recent” is defined by the last-modifying commit time from `git blame` (`%ct`, epoch seconds).

This is useful when you suspect a regression or a bug is likely to be in new code and you want to find it faster than with baseline scheduling alone.

### How it works (high-level)

1. **Build time (once per final binary)**:
   - A small LLVM pass records a mapping from SanitizerCoverage `trace-pc-guard` indices to source locations (`file:line`) for each object file.
   - At the final link step (still via the `libafl_cc` wrapper), those per-object mappings are merged and `git blame` is used to turn `file:line` into an epoch timestamp.
   - The result is written as a single binary vector mapping file:
     - `u64 head_time_epoch_seconds`
     - `u64 len`
     - `len * u64` entries where `entries[index] = epoch_seconds`
2. **Fuzzer startup**:
   - The fuzzer loads the mapping file into state metadata (`GitRecencyMapMetadata`).
3. **Scheduling/scoring**:
   - Each testcase gets a cached “recentness” timestamp: `tc_time = max(entries[idx])` over its covered indices (`MapIndexesMetadata`).
   - The scheduler boosts the testcase weight by `1 + alpha * decay(tc_time)`, where:
     - `age = head_time - tc_time`
     - `decay = 2^(-age / half_life)` and `half_life = 14 days`
   - Unknown or unmapped locations are treated as “old” (no boost).

### How to use it

#### 1) Generate the mapping file at build time

The mapping is **opt-in** and is generated only if you set:

- `LIBAFL_GIT_RECENCY_MAPPING_PATH=/path/to/git_recency_map.bin`

Then build your target with a `libafl_cc`-based wrapper (many example fuzzers ship one under `fuzzers/**/src/bin/libafl_cc.rs`).

Example (build the provided wrappers, then use them as `CC`/`CXX`):

```sh
# Build the wrappers
cargo build --release -p forkserver_libafl_cc --bin libafl_cc
cargo build --release -p forkserver_libafl_cc --bin libafl_cxx

export CC="$(pwd)/target/release/libafl_cc"
export CXX="$(pwd)/target/release/libafl_cxx"

# Enable mapping generation (written at the final link step)
export LIBAFL_GIT_RECENCY_MAPPING_PATH="$(pwd)/git_recency_map.bin"

# Build your target using the wrappers (example)
make CC="$CC" CXX="$CXX" -j"$(nproc)"
```

Notes:
- This feature uses SanitizerCoverage `trace-pc-guard` indices. Your target must be compiled with that instrumentation.
- Debug info (`-g`) is required to map coverage sites to `file:line` (the wrappers add `-g` by default).
- v1 limitation: static archives (`.a`) on the link line are **not supported** for mapping generation.

#### 2) Use the git-aware scheduler in your fuzzer

At fuzzer startup:

- Load the mapping file into the state (`GitRecencyMapMetadata`).
- Ensure your map observer enables index tracking (`.track_indices()`), so `MapIndexesMetadata` is available.
- Switch from `StdWeightedScheduler` to `GitAwareStdWeightedScheduler` (or use `GitRecencyTestcaseScore` directly).

The bias strength is controlled via `GitRecencyConfigMetadata { alpha }` (default `alpha = 2.0`).

Minimal sketch (exact types vary by fuzzer):

```rust
use libafl::{
    HasMetadata,
    observers::{CanTrack, StdMapObserver},
    schedulers::{
        GitAwareStdWeightedScheduler, GitRecencyConfigMetadata, GitRecencyMapMetadata,
    },
};

// Important: enable index tracking so MapIndexesMetadata exists.
let edges_observer = StdMapObserver::owned("edges", vec![0u8; 65536]).track_indices();

// Load the mapping generated at build time (see LIBAFL_GIT_RECENCY_MAPPING_PATH).
state.add_metadata(GitRecencyMapMetadata::load_from_file("git_recency_map.bin")?);
state.add_metadata(GitRecencyConfigMetadata::new(2.0));

let scheduler = GitAwareStdWeightedScheduler::new(&mut state, &edges_observer);
```

## Core concepts

`LibAFL` is fast, multi-platform, `no_std` compatible, and scales over cores and machines. It offers a main crate that provide building blocks for custom fuzzers, [libafl](./crates/libafl), a library containing common code that can be used for targets instrumentation, [libafl_targets](./crates/libafl_targets), and a library providing facilities to wrap compilers, [libafl_cc](./crates/libafl_cc). It offers integrations with popular instrumentation frameworks. At the moment, the supported backends are:

- `SanitizerCoverage`, in [libafl_targets](./crates/libafl_targets)
- `Frida`, in [libafl_frida](./crates/libafl_frida)
- `QEMU` user-mode and system mode, including hooks for emulation, in [libafl_qemu](./crates/libafl_qemu)
- `TinyInst`, in [libafl_tinyinst](./crates/libafl_tinyinst) by [elbiazo](https://github.com/elbiazo)

## Building and installing

#### Install the Dependencies

- **The Rust development language**
  - We highly recommend *not* to use e.g. your Linux distribution package as this is likely outdated. So rather install Rust directly, instructions can be found [here](https://www.rust-lang.org/tools/install).
  - The minimum supported Rust version is defined. You can always check the currently required version in LibAFL’s [Cargo.toml](https://github.com/AFLplusplus/LibAFL/blob/main/crates/libafl/Cargo.toml):

    If your installed Rust version is older than the one listed in Cargo.toml, update to the latest stable toolchain:

    ```bash
    rustup update stable
    ```
- **LLVM tools**
  - The LLVM tools (including clang, clang++) are needed (newer than LLVM 15.0.0 up to LLVM 18.1.3) If you are using Debian/Ubuntu, again, we highly recommmend that you install the package from [here](https://apt.llvm.org/)
  - (In `libafl_concolic`, we only support LLVM version newer than 18)
- Just:
  - We use [just](https://github.com/casey/just) to build the fuzzers in `fuzzers/` directory. You can find instructions to install it in your environment [in the Just Programmer's Manual](https://just.systems/man/en/packages.html).

#### Clone the `LibAFL` repository with

```sh
git clone https://github.com/kevin-valerio/LibAFL-history-aware.git
```

#### Build the library using

```sh
cargo build --release
```

#### Build the API documentation with

```sh
cargo doc
```

#### Browse the `LibAFL` book (WIP!) with (requires [mdbook](https://rust-lang.github.io/mdBook/index.html))

```sh
cd docs && mdbook serve
```

## Getting started

We collect all example fuzzers in [`./fuzzers`](./fuzzers/).
Be sure to read their documentation (and source), this is *the natural way to get started!*

```sh
just run
```

You can run each example fuzzer with this following command, as long as the fuzzer directory has a `Justfile` file. The best-tested fuzzer is [`./fuzzers/inprocess/libfuzzer_libpng`](./fuzzers/inprocess/libfuzzer_libpng), a multicore libfuzzer-like fuzzer using `LibAFL` for a libpng harness.

### Resources

- [Installation guide](./docs/src/getting_started/setup.md)
- [Online API documentation](https://docs.rs/libafl/)
- The `LibAFL` book (WIP) [online](https://aflplus.plus/libafl-book) or in the [repo](./docs/src/)
- Git-aware scheduling plan: [`docs/plans/git-aware-recent-coverage-scheduler.md`](./docs/plans/git-aware-recent-coverage-scheduler.md)
- Our research [paper](https://www.s3.eurecom.fr/docs/ccs22_fioraldi.pdf)
- Our RC3 [talk](http://www.youtube.com/watch?v=3RWkT1Q5IV0 "Fuzzers Like LEGO") explaining the core concepts
- Our Fuzzcon Europe [talk](https://www.youtube.com/watch?v=PWB8GIhFAaI "LibAFL: The Advanced Fuzzing Library") with a (a bit but not so much outdated) step-by-step discussion on how to build some example fuzzers
- The Fuzzing101 [solutions](https://github.com/epi052/fuzzing-101-solutions) & series of [blog posts](https://epi052.gitlab.io/notes-to-self/blog/2021-11-01-fuzzing-101-with-libafl/) by [epi](https://github.com/epi052)
- Blogpost on binary-only fuzzing lib `libaf_qemu`, [Hacking TMNF - Fuzzing the game server](https://blog.bricked.tech/posts/tmnf/part1/), by [RickdeJager](https://github.com/RickdeJager).
- [A LibAFL Introductory Workshop](https://www.atredis.com/blog/2023/12/4/a-libafl-introductory-workshop), by [Jordan Whitehead](https://github.com/jordan9001)

## Contributors

`LibAFL` is written and maintained by

- [Andrea Fioraldi](https://twitter.com/andreafioraldi) <andrea@aflplus.plus>
- [Dominik Maier](https://bsky.app/profile/dmnk.bsky.social) <dominik@aflplus.plus>
- [s1341](https://twitter.com/srubenst1341) <github@shmarya.net>
- [Dongjia Zhang](https://github.com/tokatoka) <toka@aflplus.plus>
- [Addison Crump](https://github.com/addisoncrump) <me@addisoncrump.info>
- [Romain Malmain](https://github.com/rmalmain) <rmalmain@pm.me>

## Contributing

Please check out **[CONTRIBUTING.md](CONTRIBUTING.md)** for the contributing guideline.

## Debugging

Your fuzzer doesn't work as expected? Try reading [DEBUGGING.md](./docs/src/DEBUGGING.md) to understand how to debug your problems.

## Cite

If you use `LibAFL` for your academic work, please cite the following paper:

```bibtex
@inproceedings{libafl,
 author       = {Andrea Fioraldi and Dominik Maier and Dongjia Zhang and Davide Balzarotti},
 title        = {{LibAFL: A Framework to Build Modular and Reusable Fuzzers}},
 booktitle    = {Proceedings of the 29th ACM conference on Computer and communications security (CCS)},
 series       = {CCS '22},
 year         = {2022},
 month        = {November},
 location     = {Los Angeles, U.S.A.},
 publisher    = {ACM},
}
```

## License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>
