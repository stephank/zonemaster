# zonemaster

DNS server library implementing just zone transfer.

[![Build Status](https://travis-ci.org/stephank/zonemaster.svg?branch=master)](https://travis-ci.org/stephank/zonemaster)

Having your DNS records dynamically generated is fun, but why put your
hodgepdoge DNS implementation on the public internet when you can rely on high
quality, battle tested software such as [NSD]?

Zonemaster is a library that deliberately implements only a small part of the
DNS protocol, namely the part that let's you synchronize with your secondary
servers running a proper DNS implementation.

The zonemaster interface is small, providing the bare minimum to generate your
DNS records on-the-fly, and notify slaves of updates.

Hide your zonemaster server from the public internet. Only your secondary
servers should be able to reach it. Let them deal with the heavy lifting!

Documentation is still a bit lacking, but take a look at [the example].

 [NSD]: http://www.nlnetlabs.nl/projects/nsd/
 [the example]: example.js
