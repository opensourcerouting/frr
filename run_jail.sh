#!/bin/sh

cd "`dirname $0`"

if [ \! -d "/usr/local/etc/frr" ]; then
    echo /usr/local/etc/frr does not exist or is not a directory.  Please create it. >&2
    exit 1
fi

if [ "$1" = "ns_inner" ]; then

    shift
    for I in `ls -1 etc`; do
        if [ "$I" = "frr" ]; then
            continue
        fi
        mount_nullfs "etc/$I" "/etc/$I"
    done
    mount -t tmpfs tmpfs /var/tmp
    mount -t tmpfs tmpfs /var/run

    # ip link set lo0 up

    exec ${PYTHON:-python} -mpytest "$@"
else
    sudo jail -cmr -f ./vm/jail.conf
    sudo jexec topotato $PWD/$0 ns_inner $@
    sudo jail -r topotato
fi
