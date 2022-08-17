# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [v0.0.4]
- WithFormats no longer accepts formats with semi-colons (;).  Matching parsers is done only one media type. Patches[#39](https://github.com/xmidt-org/clortho/issues/39).
- Parser.Parse strips any MIME parameters prior to looking up the parser associated with a format
- Feature/fx integration [#20](https://github.com/xmidt-org/clortho/issues/20)

## [v0.0.3]
- clorthofx package provides integration with go.uber.org/fx [#20](https://github.com/xmidt-org/clortho/issues/20)
- clorthozap package provides basic integration with go.uber.org/zap [#22](https://github.com/xmidt-org/clortho/issues/22)
- updated github.com/lestrrat-go/jwx to 2.0.0
- clorthometrics package provides integration with Prometheus [#21](https://github.com/xmidt-org/clortho/issues/21)

## [v0.0.2]
- Loader and Parser as low-level primitives for retrieving key material
- Fetcher as the higher-level API for retrieving key material
- KeyRing as a client-side cache of keys
- Resolver for resolving keys by kid on demand
- Refresher for asynchronously updating keys from one or more sources

## [v0.0.1]
- Initial creation

[Unreleased]: https://github.com/xmidt-org/clortho/compare/v0.0.4..HEAD
[v0.0.4]: https://github.com/xmidt-org/clortho/compare/v0.0.3...v0.0.4
[v0.0.3]: https://github.com/xmidt-org/clortho/compare/v0.0.2...v0.0.3
[v0.0.2]: https://github.com/xmidt-org/clortho/compare/v0.0.1...v0.0.2
[v0.0.1]: https://github.com/xmidt-org/clortho/releases/v0.0.1
