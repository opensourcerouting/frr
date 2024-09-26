#!/usr/local/bin/bash

pkg install -y git autoconf automake libtool gmake json-c pkgconf \
    bison py39-pytest c-ares py39-sphinx texinfo libunwind libyang2 protobuf-c

pw groupadd frr -g 101
pw groupadd frrvty -g 102
pw adduser frr -g 101 -u 101 -G 102 -c "FRR suite" \
    -d /usr/local/etc/frr -s /usr/sbin/nologin


cd /home/vagrant
git clone https://github.com/frrouting/frr.git --single-branch frr
cd frr
./bootstrap.sh
export MAKE=gmake LDFLAGS=-L/usr/local/lib CPPFLAGS=-I/usr/local/include
./configure \
    --sysconfdir=/usr/local/etc/frr \
    --enable-pkgsrcrcdir=/usr/pkg/share/examples/rc.d \
    --localstatedir=/var/run/frr \
    --prefix=/usr/local \
    --enable-multipath=64 \
    --enable-user=frr \
    --enable-group=frr \
    --enable-vty-group=frrvty \
    --enable-configfile-mask=0640 \
    --enable-logfile-mask=0640 \
    --enable-fpm \
    --with-pkg-git-version \
    --with-pkg-extra-version=-MyOwnFRRVersion
gmake
gmake check
gmake install

mkdir /usr/local/etc/frr
touch /usr/local/etc/frr/frr.conf

sysctl -w net.inet.ip.forwarding=1
sysctl -w net.inet6.ip6.forwarding=1

service sysctl restart