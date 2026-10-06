# clortho

clortho provides clientside management for cryptographic keys.

[![Build Status](https://github.com/xmidt-org/clortho/actions/workflows/ci.yml/badge.svg)](https://github.com/xmidt-org/clortho/actions/workflows/ci.yml)
[![codecov.io](http://codecov.io/github/xmidt-org/clortho/coverage.svg?branch=main)](http://codecov.io/github/xmidt-org/clortho?branch=main)
[![Apache V2 License](http://img.shields.io/badge/license-Apache%20V2-blue.svg)](https://github.com/xmidt-org/clortho/blob/main/LICENSE)
[![GitHub Release](https://img.shields.io/github/release/xmidt-org/clortho.svg)](https://github.com/xmidt-org/clortho/releases)
[![GoDoc](https://pkg.go.dev/badge/github.com/xmidt-org/clortho)](https://pkg.go.dev/github.com/xmidt-org/clortho)

## Summary

clortho manages cryptographic keys, either locally supplied or remotely hosted.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Details](#details)
- [Install](#install)
- [Contributing](#contributing)

## Code of Conduct

This project and everyone participating in it are governed by the [XMiDT Code Of Conduct](https://xmidt.io/docs/community/code_of_conduct/). 
By participating, you agree to this Code.

## Details

clortho supplies the keys a service needs to verify JWS signatures, such as
those on JWTs, as a `jws.KeyProvider` for
[jwx](https://github.com/lestrrat-go/jwx).  It makes three kinds of provider,
for three ways a service can come by its keys.

A `KeySetProvider` is for a server that publishes its keys as a set.  It polls
each configured source for its complete key set, keeps the keys in one map by
key ID, and answers jwx's `FetchKeys` from that map.  It never fetches a key
on demand, so a token cannot cause a request.

A `PerKeyProvider` is for a server that serves one key per request and no key
set.  It fetches a key when a token names it, and holds it.  Because that key
ID comes from a token nobody has verified yet, its configuration limits how
often such fetches can happen.

A `FixedKeyProvider` is for keys written into the service's own
configuration, as PEM or as JWKs.  It never sends a request.

Each kind is configured by a plain struct, `KeySetConfig`, `PerKeyConfig`, or
`FixedKeyConfig`, with no functional options.  For the two kinds that reach a
server, the caller supplies the `*http.Client`.  `clorthozap` and
`clorthometrics` log and count what those two do.  `clorthofx` builds any
number of providers of every kind for a
[go.uber.org/fx](https://github.com/uber-go/fx) application, and presents
them to it as one.

The package documentation at
[pkg.go.dev/github.com/xmidt-org/clortho](https://pkg.go.dev/github.com/xmidt-org/clortho)
has the full overview, including the readiness and rotation behavior.

## Install

go get -u github.com/xmidt-org/clortho

## Contributing

Refer to [CONTRIBUTING.md](CONTRIBUTING.md).
