# Zaman — SIP monitoring
#   make build   → bin/zaman-core
#   make smoke   → end-to-end test
#   make demo    → core + dashboard on high ports

export PATH := $(HOME)/.local/bin:$(PATH)

SIP_PORT  ?= 5060
HEP_PORT  ?= 9060
API_PORT  ?= 9090
CORE_URL  ?= http://127.0.0.1:$(API_PORT)

.PHONY: all build core run-core run-web run demo smoke clean doctor check

all: build

# ---- toolchain ----

doctor:
	@command -v mako >/dev/null || (echo "mako not found — https://mako-lang.dev"; exit 1)
	@command -v weft >/dev/null || (echo "weft not found — https://weft.dev"; exit 1)
	@mako version
	@weft version

# ---- build ----

build: bin/zaman-core

bin/zaman-core: core/main.mko
	mkdir -p bin
	mako build --release core/main.mko -o bin/zaman-core

core: bin/zaman-core

check: core/main.mko web/main.weft
	weft check web/main.weft

# ---- run ----

run-core: bin/zaman-core
	./bin/zaman-core $(SIP_PORT) $(HEP_PORT) $(API_PORT)

run-web:
	ZAMAN_CORE=$(CORE_URL) weft run web/main.weft

run: bin/zaman-core
	@echo "Core: SIP=$(or $(DEMO_SIP),15060) HEP=$(or $(DEMO_HEP),19060) API=$(or $(DEMO_API),19090)"
	@echo "Then: make run-web CORE_URL=http://127.0.0.1:$(or $(DEMO_API),19090)"
	./bin/zaman-core $(or $(DEMO_SIP),15060) $(or $(DEMO_HEP),19060) $(or $(DEMO_API),19090)

demo: bin/zaman-core
	./scripts/demo.sh

# ---- test ----

smoke: bin/zaman-core
	./scripts/smoke.sh

test: bin/zaman-core
	./scripts/test_integration.sh sqlite

test-load: bin/zaman-core
	./scripts/test_load.sh 1000 10

# ---- clean ----

clean:
	rm -rf bin .mako
