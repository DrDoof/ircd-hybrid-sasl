# SASL for ircd-hybrid + Anope
# Build both Docker images from upstream sources + patches
#
# Usage:
#   make build-ircd    — build ircd-hybrid image with m_sasl
#   make build-anope   — build Anope image with SASL patch
#   make build         — build both
#   make test          — quick SASL handshake test via netcat

IRCD_VERSION   ?= 8.2.47
ANOPE_BRANCH   ?= 2.1
IRCD_IMAGE     ?= hybrid-ircd:sasl
ANOPE_IMAGE    ?= anope:sasl
PLATFORM       ?= linux/amd64

.PHONY: build build-ircd build-anope test clean

build: build-ircd build-anope

# --- ircd-hybrid with m_sasl ---

build-ircd:
	docker build --platform $(PLATFORM) \
		-t $(IRCD_IMAGE) \
		-f docker/Dockerfile .

# --- Anope with SASL patch ---

build-anope: .anope-src-patched
	docker build --platform $(PLATFORM) \
		-t $(ANOPE_IMAGE) \
		-f anope-patch/Dockerfile anope-patch/

.anope-src-patched:
	@echo "==> Cloning Anope $(ANOPE_BRANCH)..."
	rm -rf anope-patch/anope-src
	git clone --depth 1 -b $(ANOPE_BRANCH) \
		https://github.com/anope/anope.git anope-patch/anope-src
	cd anope-patch/anope-src && git submodule update --init
	@echo "==> Applying SASL patch..."
	cd anope-patch/anope-src && patch -p1 < ../hybrid.cpp.patch
	touch .anope-src-patched

# --- Test ---

test:
	@echo "==> Testing SASL on localhost:6667..."
	@printf 'CAP LS 302\r\nCAP REQ :sasl\r\nAUTHENTICATE PLAIN\r\nQUIT\r\n' \
		| nc -w 5 127.0.0.1 6667 || true

# --- Clean ---

clean:
	rm -rf anope-patch/anope-src .anope-src-patched
