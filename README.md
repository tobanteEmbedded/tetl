# TAETL - Embedded Template Library

The tobanteAudio embedded template library is intended for micro controller where the `STL` is not available. Designed to have a similar API. This library supports `AVR/Arduino` micro controllers.

## Status

| **License**                                                                                                                 | **Issues**                                                                                                                     | **Code Coverage**                                                                                                              | **Codacy**                                                                                                                                                                                                                                                |
| --------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [![License](https://img.shields.io/badge/License-BSD%202--Clause-orange.svg)](https://opensource.org/licenses/BSD-2-Clause) | [![GitHub issues](https://img.shields.io/github/issues/tobanteAudio/taetl.svg)](https://GitHub.com/tobanteAudio/taetl/issues/) | [![codecov](https://codecov.io/gh/tobanteAudio/taetl/branch/master/graph/badge.svg)](https://codecov.io/gh/tobanteAudio/taetl) | [![Codacy Badge](https://api.codacy.com/project/badge/Grade/80518b423ad649649e782a3773d4e17b)](https://app.codacy.com/app/tobanteAudio/taetl?utm_source=github.com&utm_medium=referral&utm_content=tobanteAudio/taetl&utm_campaign=Badge_Grade_Dashboard) |

### Hosted

| **Standard** | **Linux - GCC**                                                                                                                                                           | **Linux - Clang**                                                                                                                                                               | **macOS**                                                                                                                                                                       | **Windows**                                                                                                                                                                           |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **C++17**    | [![GCC C++17](https://github.com/tobanteAudio/taetl/workflows/GCC%20C++17/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22GCC+C%2B%2B17%22) | [![Clang C++17](https://github.com/tobanteAudio/taetl/workflows/Clang%20C++17/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22Clang+C%2B%2B17%22) | [![macOS C++17](https://github.com/tobanteAudio/taetl/workflows/macOS%20C++17/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22macOS+C%2B%2B17%22) | [![Windows C++17](https://github.com/tobanteAudio/taetl/workflows/Windows%20C++17/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22Windows+C%2B%2B17%22) |
| **C++20**    | [![GCC C++20](https://github.com/tobanteAudio/taetl/workflows/GCC%20C++20/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22GCC+C%2B%2B20%22) | [![Clang C++20](https://github.com/tobanteAudio/taetl/workflows/Clang%20C++20/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22Clang+C%2B%2B20%22) | [![macOS C++20](https://github.com/tobanteAudio/taetl/workflows/macOS%20C++20/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22macOS+C%2B%2B20%22) | [![Windows C++20](https://github.com/tobanteAudio/taetl/workflows/Windows%20C++20/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22Windows+C%2B%2B20%22) |

### Freestanding

| **Standard** | **AVR - GCC**                                                                                                                                                             | **ARM - GCC**                                                                                                                                                             |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **C++17**    | [![AVR C++17](https://github.com/tobanteAudio/taetl/workflows/AVR%20C++17/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22AVR+C%2B%2B17%22) | [![ARM C++17](https://github.com/tobanteAudio/taetl/workflows/ARM%20C++17/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22ARM+C%2B%2B17%22) |
| **C++20**    | [![AVR C++20](https://github.com/tobanteAudio/taetl/workflows/AVR%20C++20/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22AVR+C%2B%2B20%22) | [![ARM C++20](https://github.com/tobanteAudio/taetl/workflows/ARM%20C++20/badge.svg)](https://github.com/tobanteAudio/taetl/actions?query=workflow%3A%22ARM+C%2B%2B20%22) |

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

For detailed examples look at the [examples](./examples) subdirectory or the test files in [tests](./tests).
