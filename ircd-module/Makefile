# Makefile for m_sasl.so — SASL module for ircd-hybrid 8.2.x
#
# Two build methods:
#   1. In-container: copy m_sasl.c into the ircd source tree and compile there
#   2. Cross-compile: use Docker to compile against ircd headers

# ircd-hybrid source tree paths (inside container or local build)
IRCD_SRC  ?= /ircd-hybrid/src
IRCD_LIBIO ?= /ircd-hybrid/libio/src

CC        = gcc
CFLAGS    = -O2 -Wall -Wextra -fPIC -shared -DHAVE_CONFIG_H
INCLUDES  = -I$(IRCD_SRC) -I$(IRCD_LIBIO)
LDFLAGS   = -shared

MODULE    = m_sasl.so
SOURCE    = m_sasl.c

.PHONY: all clean docker-build install

# Build locally (when inside ircd-hybrid build environment)
all: $(MODULE)

$(MODULE): $(SOURCE)
	$(CC) $(CFLAGS) $(INCLUDES) -o $@ $< $(LDFLAGS)

# Build inside Docker using the hybrid-ircd container's source tree
# Assumes the hybrid-ircd image has sources at /ircd-hybrid/
docker-build:
	docker run --rm \
		--platform linux/amd64 \
		-v "$(PWD)":/build \
		-w /build \
		hybrid-ircd-builder:latest \
		make all IRCD_SRC=/ircd-hybrid/src IRCD_LIBIO=/ircd-hybrid/libio/src

# Alternative: compile inside a running hybrid-ircd container
# Usage: make container-build CONTAINER=hybrid-ircd-container-name
CONTAINER ?= hybrid-ircd
container-build:
	docker cp $(SOURCE) $(CONTAINER):/tmp/m_sasl.c
	docker exec $(CONTAINER) sh -c '\
		cd /tmp && \
		gcc -O2 -Wall -fPIC -shared \
			-I/ircd-hybrid/src -I/ircd-hybrid/libio/src \
			-DHAVE_CONFIG_H \
			-o m_sasl.so m_sasl.c'
	docker cp $(CONTAINER):/tmp/m_sasl.so ./$(MODULE)

# Install into ircd modules directory
MODULES_DIR ?= /ircd-hybrid/modules/autoload
install: $(MODULE)
	install -m 755 $(MODULE) $(MODULES_DIR)/

clean:
	rm -f $(MODULE)
