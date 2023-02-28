ringshot
========

On demand packet capture shots over a TPACKET_V3 rx ringbuffer.

Installation
------------

Ringshot works with Linux with Python 3.6 and above.

Quick Start
-----------

For taking capture of all interfaces:

```ringshot.py -- <command>```

For taking capture of a specific interface (eth0 in below example):

```ringshot.py -i eth0 -- <command>```

`<command>` should be anything that populates notification when we need a packet
capture.

testing
-------

See requirements-dev.txt for dependencies for Python dependencies. Additionally,
iproute is required. Noting that testing suite requires network admin
capability.

To run test: `pytest test_ringshot.py --log-level=DEBUG`
