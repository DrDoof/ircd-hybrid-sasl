FROM alpine:3.21

# Install dependencies
RUN apk add --no-cache \
    build-base \
    openssl-dev \
    flex \
    bison \
    git \
    autoconf \
    automake \
    libtool \
    curl \
    wget \
    gawk \
    jansson-dev

# Create ircd user
RUN adduser -D -s /bin/sh ircd

# Download ircd-hybrid 8.2.47 source
WORKDIR /tmp
RUN wget https://github.com/ircd-hybrid/ircd-hybrid/archive/refs/tags/8.2.47.tar.gz && \
    tar xzf 8.2.47.tar.gz && \
    rm 8.2.47.tar.gz

# Apply SASL UID guard: wrap UID assignment in if (client->id[0] == '\0')
# This prevents duplicate UID when m_sasl.c assigns UID early during AUTHENTICATE
COPY patch_user.awk /tmp/
RUN cd /tmp/ircd-hybrid-8.2.47/src && \
    gawk -f /tmp/patch_user.awk user.c > user.c.tmp && \
    mv user.c.tmp user.c && \
    echo "=== Patched user.c (UID guard) ===" && \
    grep -A 10 'Guard: skip UID' user.c && \
    sed -i '1i #include <signal.h>' ircd_signal.h

# Build and install ircd-hybrid
RUN cd /tmp/ircd-hybrid-8.2.47 && \
    ./configure --prefix=/ircd-bin --enable-openssl && \
    make && \
    make install

# Compile m_sasl.so against the source tree (before cleanup)
COPY m_sasl.c /tmp/
RUN cd /tmp && \
    gcc -O2 -Wall -fPIC -shared \
        -I/tmp/ircd-hybrid-8.2.47 \
        -I/tmp/ircd-hybrid-8.2.47/src \
        -I/tmp/ircd-hybrid-8.2.47/libio/src \
        -DHAVE_CONFIG_H \
        -o m_sasl.so m_sasl.c && \
    cp m_sasl.so /ircd-bin/lib/ircd-hybrid/modules/m_sasl.so && \
    printf '%s\n' \
        "# m_sasl.la - a libtool library file" \
        "dlname='m_sasl.so'" \
        "library_names='m_sasl.so m_sasl.so m_sasl.so'" \
        "old_library=''" \
        "inherited_linker_flags=''" \
        "dependency_libs=' -lssl -lcrypto -ljansson'" \
        "weak_library_names=''" \
        "current=0" \
        "age=0" \
        "revision=0" \
        "installed=yes" \
        "shouldnotlink=yes" \
        "dlopen=''" \
        "dlpreopen=''" \
        "libdir='/ircd-bin/lib/ircd-hybrid/modules'" \
        > /ircd-bin/lib/ircd-hybrid/modules/m_sasl.la

# Cleanup source and build tools
RUN rm -rf /tmp/ircd-hybrid-8.2.47 /tmp/m_sasl.c /tmp/m_sasl.so /tmp/patch_user.awk

# Setup directories
RUN mkdir -p /ircd-bin/var/log && \
    mkdir -p /ircd-bin/var/run && \
    chown -R ircd:ircd /ircd-bin

WORKDIR /ircd-bin

# Expose ports
EXPOSE 6667 6697 7000 7001

# Create startup script
RUN echo '#!/bin/sh' > /ircd-bin/run.sh && \
    echo 'chown -R ircd:ircd /ircd-bin/var/log' >> /ircd-bin/run.sh && \
    echo 'su -s /bin/sh ircd -c "/ircd-bin/bin/ircd -foreground"' >> /ircd-bin/run.sh && \
    chmod +x /ircd-bin/run.sh

CMD ["/ircd-bin/run.sh"]
