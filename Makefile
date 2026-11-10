# Sallyport developer entry points. `make lint test` is the per-task gate (CLAUDE.md).
CARGO ?= cargo --locked
MUSL  := x86_64-unknown-linux-musl

.PHONY: lint fmt clippy deny forbid-unsafe test test-scripts nextest coverage mutants zizmor shim shim-check fuzz redteam redteam-gpu e2e-gpu doctor

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

# Shell-script tests (doctor's --redact filter).
test-scripts:
	bash tests/scripts/redact_test.sh

# CI runner (AMENDMENTS-01 §15). nextest skips doctests, so they run separately.
nextest:
	$(CARGO) nextest run --workspace --no-fail-fast
	$(CARGO) test -q --workspace --doc

# Line-coverage gates (CLAUDE.md): sally-core >= 90%. sallyd policy/approvals/egress (>= 85%) join
# when those modules exist.
COV_MIN_CORE ?= 90
coverage:
	$(CARGO) llvm-cov -q -p sally-core --summary-only --fail-under-lines $(COV_MIN_CORE)

# Mutation testing over the deny paths, zero survivors (AMENDMENTS-01 §15): a surviving mutant in
# a deny path is an untested control. egress::policy, approvals and tools::fs join as they land.
MUTANTS_FILES := crates/sally-core/src/manifest/validate/*.rs crates/sally-core/src/manifest/paths.rs \
                 crates/sally-core/src/manifest/host.rs crates/sally-core/src/config.rs
# cargo-mutants copies the tree to $$TMPDIR; /tmp is denylisted for mounts, so the copy (and the
# test fixtures under its target dir) must live elsewhere. Move the fixtures, not the wall.
MUTANTS_TMP := $(CURDIR)/target/mutants-tmp
mutants:
	mkdir -p $(MUTANTS_TMP)
	TMPDIR=$(MUTANTS_TMP) cargo mutants --package sally-core --no-shuffle $(foreach f,$(MUTANTS_FILES),--file $(f))

# GitHub Actions static analysis.
zizmor:
	zizmor --min-severity low .github/workflows

# Fuzz smoke: 60 s per target (needs nightly + cargo-fuzz; CI pins both).
FUZZ_TARGETS := manifest secrets audit_line
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

# Red-team targets arrive with task 13; until then they fail loudly rather than pass vacuously.
redteam redteam-gpu e2e-gpu:
	@echo "$@: not implemented yet (M1 task 13)"; exit 1
