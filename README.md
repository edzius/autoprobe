# Autoprobe

Kernel modules automatic probing utility.

## Motivation

So far it seems there is limited number players in field
for loading kernel modules:

* systemd -- embeds own modules loading service
* kmod -- non-systemd solution, big and feature-rich
* kmodloader -- OpenWRT lightweith solution as part of ubox

Motivation to create yet another one, is the need for
lightweight solution for embedded systems which could
work with pre-built module.dep. Typical case for yocto
based lightweight distros. This utility addresses just
that use case.

# Features

* Load configured modules
* Load all installed modules
* Unload all loaded modules
