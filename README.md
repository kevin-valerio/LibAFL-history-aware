# LibAFL-history-aware

This is a fork of [`AFLplusplus/LibAFL`](https://github.com/AFLplusplus/LibAFL).

The main goal is simple: keep coverage-guided fuzzing, but also prefer testcases that run code changed recently (based on `git blame`).

## What this adds

It adds an opt-in scheduler score that boosts testcases which cover recently changed lines.
“Recent” means the last commit time from `git blame` (`%ct`, epoch seconds).

## How it works

At build time, `libafl_cc` creates a mapping from SanitizerCoverage `trace-pc-guard` map indexes to `git blame` timestamps.
At runtime, the fuzzer loads that mapping and the scheduler uses it to bias corpus selection.

The mapping file format is:

`u64 head_time` + `u64 len` + `len * u64 entries` (all little-endian).

## How to use it

### 1) Build your target and generate the mapping

Set `LIBAFL_GIT_RECENCY_MAPPING_PATH` to where you want the mapping file.
Then build your target using a `libafl_cc` wrapper so the mapping can be created at the final link step.

Example:

```sh
cargo build --release -p forkserver_libafl_cc --bin libafl_cc
cargo build --release -p forkserver_libafl_cc --bin libafl_cxx

export CC="$(pwd)/target/release/libafl_cc"
export CXX="$(pwd)/target/release/libafl_cxx"
export LIBAFL_GIT_RECENCY_MAPPING_PATH="$(pwd)/git_recency_map.bin"

make CC="$CC" CXX="$CXX" -j"$(nproc)"
```

Notes: you must use `-fsanitize-coverage=trace-pc-guard` and have debug info (`-g`) so coverage sites can be mapped to `file:line`.
v1 does not support `.a` archives on the link line for mapping generation.

### 2) Use the git-aware scheduler

Enable index tracking on your map observer (`.track_indices()`), load the mapping file into state, then use the git-aware weighted scheduler.

Minimal sketch (exact types vary by fuzzer):

```rust
use libafl::{
    HasMetadata,
    observers::{CanTrack, StdMapObserver},
    schedulers::{GitAwareStdWeightedScheduler, GitRecencyConfigMetadata, GitRecencyMapMetadata},
};

let edges_observer = StdMapObserver::owned("edges", vec![0u8; 65536]).track_indices();

state.add_metadata(GitRecencyMapMetadata::load_from_file("git_recency_map.bin")?);
state.add_metadata(GitRecencyConfigMetadata::new(2.0)); // optional, default is 2.0

let scheduler = GitAwareStdWeightedScheduler::new(&mut state, &edges_observer);
```

For the full plan, see `docs/plans/git-aware-recent-coverage-scheduler.md`.

## License

Same license as upstream `LibAFL`: MIT or Apache-2.0 (see `LICENSE-MIT` and `LICENSE-APACHE`).
