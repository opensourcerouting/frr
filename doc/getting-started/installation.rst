:description: Topotato installation 

=========================
Installing topotato
=========================


Package installation
--------------------

Topotato lives inside FRR project so there is no installation for topotato itself.
What is needed is to install its dependencies.

.. note::
    ``topotato`` requires Python >= 3.8

Run theses commands below:


.. code-block:: bash

    sysctl -w kernel.unprivileged_userns_clone=1


.. code-block::
   :caption: Required packages

    apt-get satisfy \
        'graphviz' 'tshark (>=4.0)' 'wireshark-common (>=4.0)' 'tini' \
        'python3 (>=3.8)' \
        'python3-pytest (>=6.1)' 'python3-pytest-xdist' \
        'python3-typing-extensions' 'python3-docutils' 'python3-pyinotify' \
        'python3-scapy (>=2.4.5)' 'python3-exabgp (>=4.2)' \
        'python3-jinja2 (>=3.1)' 'python3-lxml' 'python3-markupsafe' \
        'wireshark-common' 'tini'


.. note::
    if you are using ``non-debian`` based distribution, you can install theses packages above and below manually

    - unshare - run program with some namespaces unshared from parent
    - nsenter - run program with namespaces of other processes
    - tini_ - Tini is a tiny init
    - dumpcap - Dump network traffic
    - ip - show / manipulate routing, network devices, interfaces and tunnels


.. _tini: https://github.com/krallin/tini