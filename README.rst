.. image:: https://img.shields.io/github/actions/workflow/status/amateja/acmepcap/python-test.yml
    :target: https://github.com/amateja/acmepcap/actions/workflows/python-test.yml
.. image:: https://img.shields.io/coveralls/amateja/acmepcap.svg
    :target: https://coveralls.io/github/amateja/acmepcap
.. image:: https://img.shields.io/pypi/v/acmepcap.svg
    :target: https://pypi.python.org/pypi/acmepcap
.. image:: https://img.shields.io/pypi/format/acmepcap.svg
    :target: https://pypi.python.org/pypi/acmepcap
.. image:: https://img.shields.io/pypi/pyversions/acmepcap.svg
    :target: https://pypi.python.org/pypi/acmepcap
.. image:: https://img.shields.io/pypi/status/acmepcap.svg
    :target: https://pypi.python.org/pypi/acmepcap
.. image:: https://img.shields.io/pypi/l/acmepcap.svg
    :target: https://pypi.python.org/pypi/acmepcap

========
acmepcap
========

Acme Packet ``sipmsg.log`` to packet capture converter.

This project is intended for users and administrators of Oracle (formerly
Acme Packet) Communications Session Border Controller (SBC) software. It
converts an Acme Packet ``sipmsg.log`` file into a packet capture (PCAP) file.
Originally inspired by
`apktlog2pcap <https://github.com/iturrovia/apktlog2pcap/>`_.

installation
============

::

    pip install acmepcap

usage
=====

Command-line help:

::

    acmepcap --help

    usage: main.py [-h] -f FILE [-c] -o OUTPUT [-t TIMEZONE]

options:

::

    -h, --help            show this help message and exit
    -f FILE, --file FILE  sipmsg.log file
    -c, --compress        compress the output packet capture file
    -o OUTPUT, --output OUTPUT
                          output packet capture file
    -t TIMEZONE, --timezone TIMEZONE
                          SBC timezone as a tz database identifier (defaults to UTC)

Minimal set of parameters (UTC assumed):

::

    acmepcap -f sipmsg.log -o my.pcap

All parameters in use:

::

    acmepcap -f sipmsg.log -o my.pcap.gz -c -t Europe/Warsaw

Questions & Answers
===================

#. Why convert ``sipmsg.log`` to a packet capture format?

   Although SIP was designed to be human-readable, working through a file with
   hundreds of SIP messages often belonging to different sessions is not easy.
   Converting to PCAP enables powerful filtering and analysis with standard
   tools. Additionally, when a call is encrypted, capturing traffic on the
   wire may not help, while sipmsg.log still provides the signaling you can
   analyze.

#. How can I obtain the ``sipmsg.log`` file?

   The sipmsg.log file is created on Acme Packet software when one of the
   following is enabled:
     - Debug mode: ``notify sipd debug`` (disable with ``notify sipd
       nodebug``)
     - Advanced Logging (see the Oracle Communications SBC Maintenance and
       Troubleshooting Guide)
     - Explicit SIP logging: ``notify sipd siplog`` (stop with ``notify sipd
       nosiplog``)
   You can download it directly from the device or as part of a log bundle
   created with ``package-logfiles`` or ``package-crashfiles``.

#. What should I set for the timezone parameter?
   Use the `tz database <https://web.cs.ucla.edu/~eggert/tz/tz-link.htm>`_
   identifier that matches the SBC timezone configured via ``timezone-set``.
   You can verify the current setting with ``show clock`` (note: it may not
   be an exact match). If omitted or incorrect, nothing bad will happen, but
   PCAP timestamps may be inaccurate.

Assumptions
===========

#. self-sufficient

   Aim to be as independent as possible and require only standard Python.
   While there are excellent libraries like
   `scapy <https://github.com/secdev/scapy/>`_, this tool strives to work with
   pure Python.

#. install or download

   Users can either install a release or download the single-file source and
   run it directly.

#. wide support

   Support as many environments as practical, without targeting exotic or
   unsupported versions.

#. simple

   Provide a command-line interface only. Implement only the essential
   protocol features needed for this conversion; do not attempt to implement
   a full protocol stack.
