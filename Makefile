# Zaman — SIP monitoring
#   make build   → bin/zaman-core + bin/zaman-web
#   make smoke   → end-to-end test
#   make demo    → core + dashboard on high ports

export PATH := $(HOME)/.local/bin:$(PATH)

SIP_PORT  ?= 5060
HEP_PORT  ?= 9060
API_PORT  ?= 9090
CORE_URL  ?= http://127.0.0.1:$(API_PORT)

.PHONY: all build core web run-core run-web run demo smoke clean doctor check

all: build

# ---- toolchain ----

doctor:
	@command -v go >/dev/null || (echo "go not found — https://go.dev"; exit 1)
	@go version

# ---- build ----

build: bin/zaman-core bin/zaman-web

bin/zaman-core: $(wildcard core-go/*.go)
	mkdir -p bin
	cd core-go && go build -o ../bin/zaman-core .

bin/zaman-web: $(wildcard web/*.go)
	mkdir -p bin
	cd web && go build -o ../bin/zaman-web .

core: bin/zaman-core

web: bin/zaman-web

check:
	cd core-go && go vet .
	cd web && go vet .

# ---- run ----

run-core: bin/zaman-core
	./bin/zaman-core $(SIP_PORT) $(HEP_PORT) $(API_PORT)

run-web: bin/zaman-web
	ZAMAN_CORE=$(CORE_URL) ./bin/zaman-web

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
	rm -rf bin .mako .makori
