.DEFAULT_GOAL := help

.PHONY: help format build test run \
	dilithium dilithium-divan \
	falcon falcon-divan \
	winternitz_ots winternitz_ots_divan \
	winternitz-ots winternitz-ots-divan \
	lms lms-divan \
	hss hss-divan \
	mayo mayo-divan \
	xmss xmss-divan \
	xmssmt xmssmt-divan xmssmt-bench-example \
	sphincs_plus sphincs_plus_divan \
	sphincs-plus sphincs-plus-divan \
	cross cross-divan \
	less less-divan \
	sqisign sqisign-divan \
	leansig leansig-divan

RUNS ?= 10
OUTPUT ?= benchmarks/results.csv
FORMAT ?= json
MESSAGE_SIZE ?=
PARAM_SET ?=

SCHEME_RUN_ARGS = -- --format $(FORMAT)$(if $(MESSAGE_SIZE), --message-size $(MESSAGE_SIZE),)
PARAM_SET_PREFIX = $(if $(PARAM_SET),PARAM_SET=$(PARAM_SET) ,)

help:
	@printf '%s\n' \
	'Workspace:' \
	'  make format' \
	'  make build' \
	'  make test' \
	'  make run RUNS=1 OUTPUT=benchmarks/results.csv' \
	'' \
	'Scheme crates:' \
	'  make dilithium            make dilithium-divan' \
	'  make falcon               make falcon-divan' \
	'  make winternitz-ots       make winternitz-ots-divan' \
	'  make lms                  make lms-divan' \
	'  make hss                  make hss-divan' \
	'  make mayo                 make mayo-divan' \
	'  make xmss                 make xmss-divan' \
	'  make xmssmt               make xmssmt-divan' \
	'  make sphincs-plus         make sphincs-plus-divan' \
	'  make cross                make cross-divan' \
	'  make less                 make less-divan' \
	'  make sqisign              make sqisign-divan' \
	'  make leansig              make leansig-divan' \
	'' \
	'Exact crate-name aliases also work:' \
	'  make winternitz_ots       make winternitz_ots_divan' \
	'  make sphincs_plus         make sphincs_plus_divan' \
	'' \
	'Optional variables:' \
	'  FORMAT=json|human' \
	'  MESSAGE_SIZE=<bytes>     # omitted by default, uses crate default (32)' \
	'  PARAM_SET=<name>         # used by lms/hss targets when set'

format:
	cargo fmt --all

build:
	cargo build --release --workspace

test:
	cargo test --workspace

run:
	cargo run --release --bin bench_runner -- --runs $(RUNS) --output $(OUTPUT)

dilithium:
	cargo run -p dilithium --bin dilithium $(SCHEME_RUN_ARGS)

dilithium-divan:
	cargo bench -p dilithium --bench dilithium_divan

falcon:
	cargo run -p falcon --bin falcon-bench $(SCHEME_RUN_ARGS)

falcon-divan:
	cargo bench -p falcon --bench falcon_divan

winternitz_ots:
	cargo run -p winternitz_ots --bin winternitz_ots $(SCHEME_RUN_ARGS)

winternitz-ots: winternitz_ots

winternitz_ots_divan:
	cargo bench -p winternitz_ots --bench winternitz_ots_divan

winternitz-ots-divan: winternitz_ots_divan

lms:
	$(PARAM_SET_PREFIX)cargo run -p lms --bin lms $(SCHEME_RUN_ARGS)

lms-divan:
	cargo bench -p lms --bench lms_divan

hss:
	$(PARAM_SET_PREFIX)cargo run -p hss --bin hss $(SCHEME_RUN_ARGS)

hss-divan:
	cargo bench -p hss --bench hss_divan

mayo:
	cargo run -p mayo --bin mayo $(SCHEME_RUN_ARGS)

mayo-divan:
	cargo bench -p mayo --bench mayo_divan

xmss:
	cargo run -p xmss-bench --bin xmss $(SCHEME_RUN_ARGS)

xmss-divan:
	cargo bench -p xmss-bench --bench xmss_divan

xmssmt:
	cargo run -p xmssmt-bench --bin xmssmt $(SCHEME_RUN_ARGS)

xmssmt-divan:
	cargo bench -p xmssmt-bench --bench xmssmt_divan

sphincs_plus:
	cargo run -p sphincs_plus --bin sphincs-plus-bench $(SCHEME_RUN_ARGS)

sphincs-plus: sphincs_plus

sphincs_plus_divan:
	cargo bench -p sphincs_plus --bench sphincs_plus_divan

sphincs-plus-divan: sphincs_plus_divan

cross:
	cargo run -p cross --bin cross $(SCHEME_RUN_ARGS)

cross-divan:
	cargo bench -p cross --bench cross_divan

less:
	cargo run -p less --bin less $(SCHEME_RUN_ARGS)

less-divan:
	cargo bench -p less --bench less_divan

sqisign:
	cargo run -p sqisign --bin sqisign $(SCHEME_RUN_ARGS)

sqisign-divan:
	cargo bench -p sqisign --bench sqisign_divan

leansig:
	cargo run -p leansig-bench --bin leansig $(SCHEME_RUN_ARGS)

leansig-divan:
	cargo bench -p leansig-bench --bench leansig_divan

xmssmt-bench-example:
	OUT_DIR=crates/xmssmt/bench/results-example BENCH_CMD='true' PARAM_SETS=XMSSMT-SHA2_20/2_256 MSG_SIZES=32 ITERATIONS=1 WARMUP_RUNS=0 RUNS=1 OPERATIONS=keygen,sign,verify PRINT_SUMMARY=1 crates/xmssmt/bench/run.sh
