# Changelog

## [1.3.0](https://github.com/stfsy/go-api-key/compare/v1.2.0...v1.3.0) (2026-10-08)


### Features

* **security:** enforce prefix validation, entropy limits, and memory zeroization ([de6d3a8](https://github.com/stfsy/go-api-key/commit/de6d3a888eae83bbe909c56c93502f5eb9185856))


### Bug Fixes

* **generator:** prevent delimiter collisions using chunked rejection sampling ([6d6960e](https://github.com/stfsy/go-api-key/commit/6d6960eb55789a646c0161b042c84a967f09e269))
* **validation:** reject empty token components ([7d2e66a](https://github.com/stfsy/go-api-key/commit/7d2e66aa1d10a1d7fe813d29a7c70c1ebd08a398))

## [1.2.0](https://github.com/stfsy/go-api-key/compare/v1.1.0...v1.2.0) (2025-09-16)


### Features

* add constant time comparison ([357ee0c](https://github.com/stfsy/go-api-key/commit/357ee0c97698e687f367ab35eeff1a5ec3863fc2))
* increase short token size ([cd535f6](https://github.com/stfsy/go-api-key/commit/cd535f6eb1dca2bf7ff3c53f9476b2cd2bdf2c00))
* make separator a rune ([1ed0c28](https://github.com/stfsy/go-api-key/commit/1ed0c287f2870fd12e8987b617b2a9070f39b438))
* validate token components ([bbbd77a](https://github.com/stfsy/go-api-key/commit/bbbd77a2b369b992fa4c1d44407a48a32cfa961d))

## [1.1.0](https://github.com/stfsy/go-api-key/compare/v1.0.0...v1.1.0) (2025-08-22)


### Features

* use argon2id as default hasher ([2d3d0ee](https://github.com/stfsy/go-api-key/commit/2d3d0eed95444c11ca302b7890077bebb8d6718c))

## 1.0.0 (2025-08-22)


### Features

* add library ([caf4366](https://github.com/stfsy/go-api-key/commit/caf436655fbff1fc2a6d087b728ea24493a0107e))
* modularize code, add additional public options for customization ([c44cd90](https://github.com/stfsy/go-api-key/commit/c44cd905867f7b025e88cb170e45cdf3f8d7e08d))
* simplify api key validation ([84578f8](https://github.com/stfsy/go-api-key/commit/84578f8266cf0f3e15cc7556c11f6e601adef101))
