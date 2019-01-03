FROM ubuntu:16.04

RUN dpkg --add-architecture i386 && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential libtool automake bison flex libglib2.0-dev \
        libc6-dev libtool-bin libc6:i386 libstdc++6:i386 && \
    apt-get install -y --no-install-recommends \
        python-pip python && \
    apt-get install -y --no-install-recommends \
        wget binutils-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

    # apt-get install -y --no-install-recommends \
    #     lib32z1 lib32ncurses5 lib32bz2-1.0 && \

# debug option (can be removed from production release)
# RUN 	apt-get install -y strace ltrace

# get afl
# RUN wget http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz
COPY pkgs/afl-latest.tgz  afl-latest.tgz

RUN mkdir -p afl-i386 && \
    tar xvfz afl-latest.tgz  --no-same-owner -C afl-i386 --strip-components 1 && \
    cp -r afl-i386 afl-x86_64 && \
    cd /afl-i386 && \
    make && \
    cd qemu_mode && \
    CPU_TARGET=i386 ./build_qemu_support.sh && \
    cd /afl-x86_64 && \
    make && \
    cd qemu_mode && \
    ./build_qemu_support.sh

VOLUME ["/input", "/cbs", "/output", "/cblib"]
WORKDIR /tmp

