:description: Writing your first topotato test

=======================
Writing your first test
=======================


Example test
------------

1. Create a new file called `test_sample.py` in topotato folder, containing a function, and a test:

.. code-block:: python

    # content of test_sample.py

    #!/usr/bin/env python3
    # SPDX-License-Identifier: GPL-2.0-or-later
    # Copyright (C) 2018-2023  YOUR NAME HERE for NetDEF, Inc.
    """
    Simple demo test for topotato.
    """

    from topotato.v1 import *

    @topology_fixture()
    def topology(topo):
        """
        [ r1 ]---[ noprot ]
        [    ]
        [    ]---[ rip ]
        [    ]
        [    ]---[ ripng ]
        [    ]
        [    ]---[ ospfv2 ]
        [    ]
        [    ]---[ ospfv3 ]
        [    ]
        [    ]---[ isisv4 ]
        [    ]
        [    ]---[ isisv6 ]
        """
        topo.router("r1").iface_to("ripng").ip6.append("fc00:0:0:1::1/64")


    class Configs(FRRConfigs):
        routers = ["r1"]

        zebra = """
        #% extends "boilerplate.conf"
        #% block main
        #%   for iface in router.ifaces
        interface {{ iface.ifname }}
        description {{ iface.other.endpoint.name }}
        no link-detect
        !
        #%   endfor
        !
        ip forwarding
        ipv6 forwarding
        !
        #% endblock
        """

        ripd = """
        #% extends "boilerplate.conf"
        #% block main
        debug rip events
        debug rip zebra
        !
        router rip
        version 2
        network {{ router.iface_to('rip').ip4[0].network }}
        #% endblock
        """

        ripngd = """
        #% extends "boilerplate.conf"
        #% block main
        debug ripng events
        debug ripng zebra
        !
        router ripng
        network {{ router.iface_to('ripng').ip6[0].network }}
        #% endblock
        """


    class AllStartupTest(TestBase, AutoFixture, topo=topology, configs=Configs):
        """
        docstring here
        """

        @topotatofunc
        def test_running(self, topo, r1):
            """
            just check that all daemons are running
            """
            for daemon in Configs.daemons:
                if not hasattr(Configs, daemon):
                    continue
                yield from AssertVtysh.make(r1, daemon, command="show version")


2. Run the following command in your command line to run the test:

.. code-block:: bash
    
    ./run_userns.sh --frr-builddir=$PATH_TO_FRR_BUILD \
                    --log-cli-level=DEBUG \
                    -v -v -x \ 
                    sameple_test.py 

3. If you should see all your test in green it means every works fine.
