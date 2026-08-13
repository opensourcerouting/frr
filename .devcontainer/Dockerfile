FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y \
        bison \
        build-essential \
        clang-format \
        cmake \
        curl \
        flex \
        gcc-13-plugin-dev \
        gdb \
        git \
        install-info \
        iproute2 \
        iputils-ping \
        iputils-tracepath \
        libc-ares-dev \
        libcap-dev \
        libelf-dev \
        libevent-dev \
        libgrpc++-dev \
        libjson-c-dev \
        libpcre2-dev \
        libprotobuf-c-dev \
        libreadline-dev \
        librtr-dev \
        libsnmp-dev \
        libtool \
        libunwind-dev \
        locales \
        net-tools \
        pkg-config \
        protobuf-c-compiler \
        protobuf-compiler-grpc \
        python3-dev \
        python3-exabgp \
        python3-pytest \
        python3-pytest-asyncio \
        python3-pytest-xdist \
        python3-scapy \
        python3-sphinx \
        snmp \
        snmp-mibs-downloader \
        snmpd \
        sudo \
        tcpdump \
        texinfo \
        tmux \
        tshark \
        valgrind \
        vim \
        ;


#
# Configure locale
#
RUN locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LANGUAGE=en_US:en
ENV LC_ALL=en_US.UTF-8


#
# Patch SNMP MIB to work with FRR
#
RUN curl -o /usr/share/snmp/mibs/ietf/SNMPv2-PDU \
      https://raw.githubusercontent.com/FRRouting/frr-mibs/main/ietf/SNMPv2-PDU


#
# Build and install libyang dependency
#
ARG LIBYANG_VERSION='2.1.128'
RUN curl -L "https://github.com/CESNET/libyang/archive/refs/tags/v${LIBYANG_VERSION}.tar.gz" \
    | tar -xvzf - -C /root \
    && cd /root/libyang-${LIBYANG_VERSION} \
    && cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=/usr -B build \
    && make -C build -j $(nproc) install


#
# Create exabgp user for topotest
#
RUN useradd -r -d /var/run/exabgp -s /bin/false exabgp


#
# Setup FRR user/groups
#
RUN groupadd --system --gid 92 frr \
    && groupadd --system --gid 85 frrvty \
    && useradd --system --gid frr --home /var/run/frr \
        --comment "FRR suite" --shell /sbin/nologin frr \
    && usermod -a -G frrvty frr


#
# Setup common user
#
ARG USERNAME=vscode
ARG USER_UID=1000
ARG USER_GID=1000
RUN userdel ubuntu \
    && groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID --shell /bin/bash --create-home $USERNAME \
    && echo "Defaults:$USERNAME env_keep += \"TMUX\"" > /etc/sudoers.d/$USERNAME \
    && echo "$USERNAME ALL=(root) NOPASSWD:ALL" >> /etc/sudoers.d/$USERNAME \
    && chmod 0440 /etc/sudoers.d/$USERNAME
USER $USERNAME

COPY frr-build /sbin/frr-build
