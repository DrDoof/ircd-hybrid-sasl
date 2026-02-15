# SASL Module for ircd-hybrid + Anope

Adds SASL PLAIN authentication support to ircd-hybrid 8.2.x with Anope 2.1 services.

## Components

| File | Purpose |
|------|---------|
| `ircd-module/m_sasl.c` | Loadable `.so` module for ircd-hybrid (AUTHENTICATE, SASL ENCAP, SVSLOGIN, MECHLIST) |
| `ircd-module/Makefile` | Build m_sasl.so (in-container or cross-compile) |
| `ircd-patch/user.c.patch` | 3-line UID guard patch for `src/user.c` (prevents duplicate UID on early assignment) |
| `anope-patch/hybrid.cpp.patch` | Adds SASL::ProtocolInterface + ENCAP handler to Anope's hybrid protocol module |

## Architecture

```
Client              ircd-hybrid (m_sasl.so)        Anope (patched hybrid.cpp)
  │                        │                              │
  │── CAP REQ :sasl ──→    │                              │
  │← CAP ACK :sasl ───     │                              │
  │── AUTHENTICATE PLAIN →  │                              │
  │                        │── ENCAP * SASL uid * H host ip ──→
  │                        │── ENCAP * SASL uid * S PLAIN ────→
  │                        │←── ENCAP SASL agent uid C + ─────│
  │← AUTHENTICATE + ──     │                              │
  │── base64(n\0n\0pw) →   │                              │
  │                        │── ENCAP SASL uid agent C b64 ──→
  │                        │←── ENCAP SVSLOGIN uid acct ─────│
  │                        │←── ENCAP SASL agent uid D S ────│
  │← 900 logged in ──     │                              │
  │← 903 SASL success ──  │                              │
  │── CAP END ────────→    │                              │
```

## Build

### 1. ircd-hybrid module (m_sasl.so)

**Option A: compile inside running container**
```bash
cd ircd-module
make container-build CONTAINER=hybrid-ircd
```

**Option B: copy source and compile manually**
```bash
docker cp ircd-module/m_sasl.c hybrid-ircd:/tmp/
docker exec hybrid-ircd sh -c '
  cd /tmp &&
  gcc -O2 -Wall -fPIC -shared \
    -I/ircd-hybrid/src -I/ircd-hybrid/libio/src \
    -DHAVE_CONFIG_H \
    -o m_sasl.so m_sasl.c'
docker cp hybrid-ircd:/tmp/m_sasl.so ./ircd-module/
```

### 2. ircd-hybrid core patch (user.c)

Apply the UID guard patch to the ircd-hybrid source and rebuild:
```bash
cd /path/to/ircd-hybrid-source
patch -p1 < /path/to/ircd-patch/user.c.patch
make clean && make && make install
```

Or if building via Docker, apply patch in the Dockerfile before `make`.

### 3. Anope hybrid.cpp patch

Apply to Anope 2.1 source and rebuild:
```bash
cd /path/to/anope-source
patch -p1 < /path/to/anope-patch/hybrid.cpp.patch
cd build && cmake .. && make -j$(nproc) && make install
```

## Deploy

### ircd-hybrid

1. Copy `m_sasl.so` into the modules autoload directory:
   ```bash
   docker cp ircd-module/m_sasl.so hybrid-ircd:/ircd-hybrid/modules/autoload/
   ```

2. Or add to `ircd.conf` modules block:
   ```
   modules {
     path = "/ircd-hybrid/modules/autoload";
     module { name = "m_sasl"; };
   };
   ```

3. Rehash or restart: `/REHASH` from IRC or restart container.

### Anope

1. Ensure these modules are enabled in `modules.conf`:
   ```conf
   module { name = "ns_sasl" }
   module { name = "ns_sasl_plain" }
   ```

2. Rebuild and restart the Anope container:
   ```bash
   cd ~/Projekty/Chatik/anope-docker
   docker compose build
   # On OCI server:
   docker compose up -d
   ```

## Verification

1. **CAP LS** shows `sasl=PLAIN`:
   ```
   CAP LS
   :server CAP * LS :... sasl=PLAIN ...
   ```

2. **Full SASL flow**:
   ```
   CAP REQ :sasl
   AUTHENTICATE PLAIN
   AUTHENTICATE <base64(nick\0nick\0password)>
   CAP END
   ```

3. **Expected responses**:
   - `903 :SASL authentication successful` on correct credentials
   - `904 :SASL authentication failed` on wrong password
   - `906 :SASL authentication aborted` on `AUTHENTICATE *`

4. **WHOIS** shows account: `330 nick account :is logged in as`

## Limits

- Max 256 concurrent SASL sessions
- Max 20 AUTHENTICATE messages per session
- Max 3 failures before rejection
- Only PLAIN mechanism (EXTERNAL can be added via Anope's ns_sasl_external)
