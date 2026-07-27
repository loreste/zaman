# Zaman — integrated SIP monitoring echo system
# Mako core + Weft HTMX/Tailwind dashboard

export PATH := $(HOME)/.local/bin:$(PATH)

SIP_PORT  ?= 5060
HEP_PORT  ?= 9060
API_PORT  ?= 9090
WEB_PORT  ?= 3000
CORE_URL  ?= http://127.0.0.1:$(API_PORT)

.PHONY: all build core web run-core run-web run demo smoke clean doctor

all: build

doctor:
	@command -v mako >/dev/null || (echo "mako not found — https://mako-lang.com"; exit 1)
	@command -v weft >/dev/null || (echo "weft not found — build from github.com/loreste32/weft"; exit 1)
	@mako version
	@weft version

build: bin/zaman-core

bin/zaman-core: core/main.mko
	mkdir -p bin
	mako build --release core/main.mko -o bin/zaman-core

core: bin/zaman-core

run-core: bin/zaman-core
	./bin/zaman-core $(SIP_PORT) $(HEP_PORT) $(API_PORT)

run-web:
	ZAMAN_CORE=$(CORE_URL) weft run web/main.weft

# High ports for local demo (no root)
run:
	@echo "Start core on SIP:$(or $(DEMO_SIP),15060) HEP:$(or $(DEMO_HEP),19060) API:$(or $(DEMO_API),19090)"
	@echo "Then: make run-web CORE_URL=http://127.0.0.1:$(or $(DEMO_API),19090)"
	./bin/zaman-core $(or $(DEMO_SIP),15060) $(or $(DEMO_HEP),19060) $(or $(DEMO_API),19090)

demo: bin/zaman-core
	./scripts/demo.sh

smoke: bin/zaman-core
	./scripts/smoke.sh

clean:
	rm -rf bin .mako
