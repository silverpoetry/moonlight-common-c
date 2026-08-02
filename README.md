# Moonlight Streaming Core Library

[![License](https://img.shields.io/github/license/silverpoetry/moonlight-common-c?style=flat-square)](LICENSE)
[![Upstream](https://img.shields.io/badge/upstream-moonlight--stream%2Fmoonlight--common--c-blue?style=flat-square)](https://github.com/moonlight-stream/moonlight-common-c)

Moonlight-common-c contains the core GameStream client code shared by Moonlight clients. This repository maintains the **`unified`** integration branch used by the companion Android client, Qt client, and Sunshine host in the silverpoetry Moonlight suite.

## Unified protocol extensions

The integration branch keeps extension framing, capability negotiation, validation, and lifecycle rules in one shared implementation instead of duplicating wire formats in each application:

- native multi-contact touchpad frames and button transitions;
- secure microphone uplink over the existing audio transport;
- negotiated clipboard synchronization for UTF-8 text and PNG images;
- lazy file and directory offers whose manifests and contents are requested only on paste;
- correlated acknowledgements, cancellation, retry classification, payload limits, and strict manifest validation.

The extensions are capability-gated. Clients must not send an extension until the peer advertises support, and the maintained applications intentionally do not carry obsolete private clipboard protocol fallbacks.

## Consumers

| Repository | Branch | Role |
| --- | --- | --- |
| [Moonlight Android](https://github.com/silverpoetry/moonlight-android) | `master` | Mobile input, clipboard, and microphone client |
| [Moonlight Qt](https://github.com/silverpoetry/moonlight-qt) | `master` | Desktop input and clipboard client |
| [Sunshine](https://github.com/silverpoetry/Sunshine) | `master` | Host-side protocol and Windows input implementation |

All three repositories pin the same `unified` commit as a Git submodule. Protocol changes should land here first, include serialization and validation tests, and then be consumed by every affected application in one coordinated release.

## Building and testing

```sh
git submodule update --init --recursive
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Moonlight-common-c requires the specific ENet revision bundled as a submodule. It contains API and ABI changes for IPv6 compatibility and retransmission behavior; linking another libenet build can crash or corrupt a session.

## Upstream and license

The upstream project is [moonlight-stream/moonlight-common-c](https://github.com/moonlight-stream/moonlight-common-c). This fork remains licensed under the [GNU General Public License v3.0](LICENSE), with upstream copyright and attribution preserved.
