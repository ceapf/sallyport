# Sallyport developer entry points. `make lint test` is the per-task gate (CLAUDE.md).
CARGO ?= cargo --locked
MUSL  := x86_64-unknown-linux-musl

.PHONY: lint fmt clippy deny forbid-unsafe test test-scripts nextest coverage mutants mutants-wide-core mutants-wide-sallyd mutants-wide-shim zizmor shim shim-check fuzz redteam redteam-gpu e2e-gpu doctor

lint: fmt clippy forbid-unsafe deny

fmt:
	$(CARGO) fmt --all -- --check

clippy:
	$(CARGO) clippy -q --workspace --all-targets -- -D warnings

deny:
	$(CARGO) deny check
	$(CARGO) deny --manifest-path fuzz/Cargo.toml check

# SI guard (defense in depth; the workspace `forbid` lint is the real enforcement):
#  - every crate opts into workspace lints, so no crate escapes `unsafe_code = "forbid"`
#  - every crate root carries the attribute as a real line (not inside a comment)
#  - no `unsafe` token in any .rs file outside comments (tests/, src/bin/, build.rs included)
forbid-unsafe:
	@for t in crates/*/Cargo.toml; do \
	  awk '/^\[lints\]/{f=1;next} /^\[/{f=0} f&&/^workspace *= *true/{ok=1} END{exit !ok}' "$$t" \
	    || { echo "missing [lints] workspace = true: $$t"; exit 1; }; \
	done
	@for d in crates/*/; do \
	  r=$$(ls $$d/src/lib.rs $$d/src/main.rs 2>/dev/null | head -n1); \
	  [ -n "$$r" ] || { echo "no lib.rs/main.rs in $$d"; exit 1; }; \
	  grep -qE '^#!\[forbid\(unsafe_code\)\]' "$$r" || { echo "missing #![forbid(unsafe_code)]: $$r"; exit 1; }; \
	done
	@! grep -rnE '\bunsafe\b' crates --include='*.rs' | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|#!\[forbid\(unsafe_code\)\])' \
	  || { echo "unsafe keyword found"; exit 1; }

test: test-scripts shim-check
	$(CARGO) test -q --workspace

# Shell-script tests (doctor's --redact filter, the commit trailer check, the mutation and
# coverage gates).
test-scripts:
	bash tests/scripts/redact_test.sh
	bash tests/scripts/check_trailers_test.sh
	bash tests/scripts/mutants_gate_test.sh
	bash tests/scripts/coverage_gate_test.sh

# CI runner (AMENDMENTS-01 §15). nextest skips doctests, so they run separately.
nextest:
	$(CARGO) nextest run --workspace --no-fail-fast
	$(CARGO) test -q --workspace --doc

# Line-coverage gates (CLAUDE.md): sally-core >= 90%; sallyd egress >= 85% over the whole module
# directory, lib tests only (architect ruling Q16, Task 8). Approvals join when they exist.
COV_MIN_CORE ?= 90
COV_MIN_EGRESS ?= 85
coverage:
	$(CARGO) llvm-cov -q -p sally-core --summary-only --fail-under-lines $(COV_MIN_CORE)
	$(CARGO) llvm-cov -q -p sallyd --lib --json --summary-only --output-path target/cov-sallyd.json
	bash scripts/coverage-gate.sh $(COV_MIN_EGRESS) target/cov-sallyd.json /crates/sallyd/src/egress/

# Mutation testing over the deny paths, zero survivors (AMENDMENTS-01 §15): a surviving mutant in
# a deny path is an untested control. egress::policy, approvals and tools::fs join as they land.
MUTANTS_FILES := crates/sally-core/src/manifest/validate/*.rs crates/sally-core/src/manifest/paths.rs \
                 crates/sally-core/src/manifest/host.rs crates/sally-core/src/config.rs
# cargo-mutants copies the tree to $$TMPDIR; /tmp is denylisted for mounts, so the copy (and the
# test fixtures under its target dir) must live elsewhere. Move the fixtures, not the wall.
MUTANTS_TMP := $(CURDIR)/target/mutants-tmp
# The gate fails on missed mutants only; a timed-out mutant hangs a test, so it counts as
# detected and goes to the job summary (maintainer ruling, #36; scripts/mutants-gate.sh).
mutants:
	mkdir -p $(MUTANTS_TMP)
	TMPDIR=$(MUTANTS_TMP) cargo mutants --package sally-core --no-shuffle $(foreach f,$(MUTANTS_FILES),--file '$(f)'); \
	  bash scripts/mutants-gate.sh $$? mutants.out

# The wider scope (CLAUDE.md "Mutation scope"): every other file whose security decisions can be
# tested without starting a container, zero survivors too. Per mutant only container-free tests
# run: the crate's unit tests plus the integration binaries that start no container (sally-core's
# all start none). Launch, teardown and the watchdog tasks stay with the rt_ tests.
# MUTANTS_SHARD=k/n runs one round-robin shard; MUTANTS_OUT=<dir> moves mutants.out.
MUTANTS_WIDE_CORE := $(addprefix crates/sally-core/src/,manifest/image.rs manifest/hostenv.rs \
                     manifest/parse.rs manifest/summary.rs manifest/units.rs secrets/store.rs \
                     secrets/secret.rs audit/entry.rs audit/redact.rs audit/verify.rs \
                     audit/writer.rs audit/layout.rs fsutil.rs fd.rs)
MUTANTS_WIDE_SALLYD := $(addprefix crates/sallyd/src/sandbox/,argv.rs check.rs types.rs profiles.rs \
                       overlap.rs scan.rs images.rs changes.rs dirs.rs podman.rs disk.rs stage.rs \
                       launch/error.rs) \
                       $(addprefix crates/sallyd/src/egress/,addr.rs authority.rs head.rs policy.rs server.rs \
                       hostaddrs.rs tunnel.rs)
MUTANTS_WIDE_SHIM := $(addprefix crates/sally-shim/src/,args.rs relay.rs)
MUTANTS_WIDE_TESTS_CORE :=
MUTANTS_WIDE_TESTS_SALLYD := --lib --test=argv --test=scan
MUTANTS_WIDE_TESTS_SHIM := --lib --test=relay
MUTANTS_SHARD ?=
MUTANTS_OUT ?=
# $(1) package, $(2) files, $(3) cargo test args
mutants_wide = mkdir -p $(MUTANTS_TMP) && TMPDIR=$(MUTANTS_TMP) cargo mutants --package $(1) \
  --no-shuffle $(if $(MUTANTS_SHARD),--shard $(MUTANTS_SHARD) --sharding round-robin) \
  $(if $(MUTANTS_OUT),--output $(MUTANTS_OUT)) $(foreach f,$(2),--file '$(f)') \
  $(foreach a,$(3),--cargo-test-arg=$(a)); \
  bash scripts/mutants-gate.sh $$? $(if $(MUTANTS_OUT),$(MUTANTS_OUT)/mutants.out,mutants.out)
mutants-wide-core:
	$(call mutants_wide,sally-core,$(MUTANTS_WIDE_CORE),$(MUTANTS_WIDE_TESTS_CORE))
mutants-wide-sallyd:
	$(call mutants_wide,sallyd,$(MUTANTS_WIDE_SALLYD),$(MUTANTS_WIDE_TESTS_SALLYD))
mutants-wide-shim:
	$(call mutants_wide,sally-shim,$(MUTANTS_WIDE_SHIM),$(MUTANTS_WIDE_TESTS_SHIM))

# GitHub Actions static analysis.
zizmor:
	zizmor --min-severity low .github/workflows

# Fuzz smoke: 60 s per target (needs nightly + cargo-fuzz; CI pins both).
FUZZ_TARGETS := manifest secrets audit_line egress_head
FUZZ_SECS ?= 60
CARGO_FUZZ_TOOLCHAIN ?= +nightly
fuzz:
	@for t in $(FUZZ_TARGETS); do \
	  cargo $(CARGO_FUZZ_TOOLCHAIN) fuzz run --fuzz-dir fuzz $$t fuzz/corpus/$$t -- -max_total_time=$(FUZZ_SECS) || exit 1; \
	done

# Static shim for the sandbox image (copied into images/sandbox-base by images/build.sh).
shim:
	$(CARGO) build --release -p sally-shim --target $(MUSL)

# The shim runs inside a sandbox with nothing to rely on: it must stay a static binary with no
# dependencies beyond std (it is part of what the sandbox trusts, so it stays small and dumb).
shim-check: shim
	@command -v readelf >/dev/null || { echo "shim-check: readelf not found (install binutils)"; exit 1; }; \
	bin=target/$(MUSL)/release/sally-shim; \
	if readelf -d $$bin | grep -q NEEDED || readelf -l $$bin | grep -q INTERP; then \
	  echo "shim-check: $$bin is not statically linked"; exit 1; fi; \
	n=$$($(CARGO) tree -p sally-shim --prefix none -e no-dev | wc -l); \
	if [ "$$n" != 1 ]; then echo "shim-check: sally-shim has dependencies besides std"; exit 1; fi; \
	echo "shim-check: ok (static, std only)"

# Redacted by default: doctor output goes into reports and issues (CLAUDE.md, public repository rules).
doctor:
	bash scripts/doctor.sh --redact

# Red-team rows implemented so far: every test named `rt_<row>_…` in the workspace (Task 6c);
# Task 13 adds the harness and the remaining M1 rows. No GPU needed. RT-AG-09 needs cgroup v2:
# without it the run fails, never skips (CLAUDE.md). An empty selection fails too.
REDTEAM_FILTER := test(/(^|::)rt_/)
REDTEAM_WSL_TEST := rt_fs_11_wsl_a_windows_executable_does_not_reach_windows
REDTEAM_WSL_FILTER := test(=$(REDTEAM_WSL_TEST))
redteam:
	@v=$$(podman info --format '{{.Host.CgroupsVersion}}'); \
	  [ "$$v" = v2 ] || { echo "redteam: cgroup v2 required (RT-AG-09), podman reports '$$v'"; exit 1; }
	$(CARGO) nextest run --workspace --no-fail-fast --no-tests=fail -E '$(REDTEAM_FILTER)'
	@# RT-FS-11's .exe part is the one approved ignored rt_ test: run on WSL, listed as skipped elsewhere.
	@if [ -e /proc/sys/fs/binfmt_misc/WSLInterop ]; then \
	  $(CARGO) nextest run --workspace --no-tests=fail --run-ignored only -E '$(REDTEAM_WSL_FILTER)'; \
	else echo "redteam: not WSL: $(REDTEAM_WSL_TEST) skipped (ignored), not passed"; fi

# GPU targets arrive with M3; until then they fail loudly rather than pass vacuously.
redteam-gpu e2e-gpu:
	@echo "$@: not implemented yet (M3)"; exit 1
