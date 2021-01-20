# TAETL - Embedded Template Library

The tobanteAudio embedded template library is intended for micro controller where the `STL` is not available. Designed to have a similar API. This library supports `AVR/Arduino` micro controllers.

## Status

| **License**                                                                                                                 | **Issues**                                                                                                                     | **Code Coverage**                                                                                                              | **Codacy**                                                                                                                                                                                                                                                |
| --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [![License](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause) | [![GitHub issues](https://img.shields.io/github/issues/tobanteAudio/taetl.svg)](https://GitHub.com/tobanteAudio/taetl/issues/) | [![codecov](https://codecov.io/gh/tobanteAudio/taetl/branch/master/graph/badge.svg)](https://codecov.io/gh/tobanteAudio/taetl) | [![Codacy Badge](https://api.codacy.com/project/badge/Grade/80518b423ad649649e782a3773d4e17b)](https://app.codacy.com/app/tobanteAudio/taetl?utm_source=github.com&utm_medium=referral&utm_content=tobanteAudio/taetl&utm_campaign=Badge_Grade_Dashboard) |

### Hosted

| **Standard** | **Linux - GCC**                                                                                                         | **Linux - Clang**                                                                                                       | **macOS**                                                                                                                                         | **Windows**                                                                                                                                             |
| ------------ | ----------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| C++17        | [![Build Status](https://travis-ci.org/tobanteAudio/taetl.svg?branch=master)](https://travis-ci.org/tobanteAudio/taetl) | [![Build Status](https://travis-ci.org/tobanteAudio/taetl.svg?branch=master)](https://travis-ci.org/tobanteAudio/taetl) | [![macOS](https://github.com/tobanteAudio/taetl/workflows/macOS/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3AmacOS) | [![Windows](https://github.com/tobanteAudio/taetl/workflows/Windows/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3AWindows) |
| C++20        |                                                                                                                         |                                                                                                                         |                                                                                                                                                   |                                                                                                                                                         |

### Freestanding

| **Standard** | **AVR - GCC**                                                                                                                               | **ARM - GCC**                                                                                                                               |     |     |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | --- | --- |
| C++17        | [![AVR](https://github.com/tobanteAudio/taetl/workflows/AVR/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3AAVR) | [![ARM](https://github.com/tobanteAudio/taetl/workflows/ARM/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3AARM) |     |     |
| C++20        |                                                                                                                                             |                                                                                                                                             |     |     |

## Quick Start

```sh
git clone https://github.com/tobanteAudio/taetl.git
```

- [Implementation Progress (Spreadsheet)](https://docs.google.com/spreadsheets/d/1-qwa7tFnjFdgY9XKBy2fAsDozAfG8lXsJXHwA_ITQqM/edit?usp=sharing)
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
