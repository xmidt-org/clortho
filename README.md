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

clortho fetches, caches, and refreshes the keys a service needs to verify JWS
signatures, such as those on JWTs, and exposes them to
[jwx](https://github.com/lestrrat-go/jwx) as a `jws.KeyProvider`.  A `KeyRing`
holds the keys, a `Refresher` keeps it current from configured sources, and
`NewKeyProvider` wraps it for verification.  An optional `Resolver` fetches
individual keys on demand for callers that need one, and `clorthofx` wires all
of it into a [go.uber.org/fx](https://github.com/uber-go/fx) application.

The package documentation at
[pkg.go.dev/github.com/xmidt-org/clortho](https://pkg.go.dev/github.com/xmidt-org/clortho)
is the full overview, including which configuration feeds verification and
which does not.

## Install

go get -u github.com/xmidt-org/clortho

## Contributing

Refer to [CONTRIBUTING.md](CONTRIBUTING.md).
