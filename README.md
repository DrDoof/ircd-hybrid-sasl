# SASL Module for ircd-hybrid + Anope

Adds SASL PLAIN authentication support to ircd-hybrid 8.2.x with Anope 2.1 services.

## Quick Start

```bash
git clone https://github.com/DrDoof/ircd-hybrid-sasl.git
cd ircd-hybrid-sasl

# Build both images
make build

# Or separately:
make build-ircd    # -> hybrid-ircd:sasl
make build-anope   # -> anope:sasl (clones Anope, patches, builds)
```

### Anope config

Enable SASL modules in `modules.conf`:
```conf
module { name = "ns_sasl" }
module { name = "ns_sasl_plain" }
```

### ircd-hybrid config

Add to `modules.conf`:
```
loadmodule "m_sasl.la";
```

## What it does

```
Client              ircd-hybrid (m_sasl.so)        Anope (patched hybrid.cpp)
  |                        |                              |
  |-- CAP REQ :sasl -->    |                              |
  |<- CAP ACK :sasl --     |                              |
  |-- AUTHENTICATE PLAIN ->|                              |
  |                        |-- ENCAP * SASL uid * S PLAIN -->
  |                        |<-- ENCAP SASL agent uid C + ----|
  |<- AUTHENTICATE + --    |                              |
  |-- base64(n\0n\0pw) ->  |                              |
  |                        |-- ENCAP SASL uid agent C b64 -->
  |                        |<-- ENCAP SVSLOGIN uid acct -----|
  |                        |<-- ENCAP SASL agent uid D S ----|
  |<- 903 SASL success --  |                              |
```

## Repository layout

```
docker/                     ircd-hybrid Docker build context
  Dockerfile                  builds ircd-hybrid 8.2.47 + m_sasl + user.c patch
  m_sasl.c                    SASL module source (copy of ircd-module/m_sasl.c)
  patch_user.awk              awk script to patch user.c UID guard
  user.c.patch                same patch in unified diff format

ircd-module/
  m_sasl.c                    canonical SASL module source
  Makefile                    standalone build (inside container or cross-compile)

ircd-patch/
  user.c.patch                3-line UID guard for src/user.c

anope-patch/
  hybrid.cpp.patch            unified diff for Anope's modules/protocol/hybrid.cpp
  Dockerfile                  Anope Docker build (used by make build-anope)

Makefile                      top-level: make build / build-ircd / build-anope / test
```

## Limits

- Max 256 concurrent SASL sessions
- Max 20 AUTHENTICATE messages per session
- Max 3 failures before rejection
- Only PLAIN mechanism (add ns_sasl_external in Anope for EXTERNAL)
