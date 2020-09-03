# TAETL - Embedded Template Library

The tobanteAudio embedded template library is intended for micro controller where the `STL` is not available. Designed to have a similar API. This library supports `AVR/Arduino` micro controllers.

## Status

|                                                           LICENSE                                                           |                                                      Linux / macOS                                                      |                                                                  Windows                                                                  |                                                                  AVR                                                                  |                                    Issues                                     |                                                         Code Coverage                                                          |                                                                                                                          Codacy                                                                                                                           |
| :-------------------------------------------------------------------------------------------------------------------------: | :---------------------------------------------------------------------------------------------------------------------: | :---------------------------------------------------------------------------------------------------------------------------------------: | :-----------------------------------------------------------------------------------------------------------------------------------: | :---------------------------------------------------------------------------: | :----------------------------------------------------------------------------------------------------------------------------: | :-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
| [![License](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause) | [![Build Status](https://travis-ci.org/tobanteAudio/taetl.svg?branch=master)](https://travis-ci.org/tobanteAudio/taetl) | [![AppVeyor Build status](https://img.shields.io/appveyor/ci/tobanteAudio/taetl.svg)](https://ci.appveyor.com/project/tobanteAudio/taetl) | [![Cirrus CI Build Status](https://api.cirrus-ci.com/github/tobanteAudio/taetl.svg)](https://cirrus-ci.com/github/tobanteAudio/taetl) | ![GitHub issues](https://img.shields.io/github/issues/tobanteAudio/taetl.svg) | [![codecov](https://codecov.io/gh/tobanteAudio/taetl/branch/master/graph/badge.svg)](https://codecov.io/gh/tobanteAudio/taetl) | [![Codacy Badge](https://api.codacy.com/project/badge/Grade/80518b423ad649649e782a3773d4e17b)](https://app.codacy.com/app/tobanteAudio/taetl?utm_source=github.com&utm_medium=referral&utm_content=tobanteAudio/taetl&utm_campaign=Badge_Grade_Dashboard) |

## Quick Start

```sh
git clone https://github.com/tobanteAudio/taetl.git
```

- [Project Integration](docs/project_integration.md)
- [Building Tests & Documentation](docs/building.md)
- [API Reference](https://tobanteaudio.github.io/taetl/index.html)
- [Examples](https://github.com/tobanteAudio/taetl/tree/master/examples)

## Design Goals

- 100% portable (no STL headers required, minimum of C headers)
- Header only
- C++17
- Similar api to the STL
- No dynamic memory
- `constexpr` all the things
- Easy desktop development (cmake)
  - Stubs for external dependencies (FreeRTOS)
- Experimental headers
  - Strong types
  - Networking (buffers, ntoh, ...)
  - FreeRTOS Abstraction
  - STM32 HAL
  - DSP DSL via Template Meta Programming

## Usage

For detailed examples look at the `examples` subdirectory or the test files in `tests`.
