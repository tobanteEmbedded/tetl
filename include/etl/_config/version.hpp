// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONFIG_VERSION_HPP
#define TETL_CONFIG_VERSION_HPP

/// \brief The major release version
// NOLINTNEXTLINE(modernize-macro-to-enum)
#define TETL_VERSION_MAJOR 0

/// \brief The minor release version
// NOLINTNEXTLINE(modernize-macro-to-enum)
#define TETL_VERSION_MINOR 4

/// \brief The patch release version
// NOLINTNEXTLINE(modernize-macro-to-enum)
#define TETL_VERSION_PATCH 0

/// \brief The library version as a string literal
#define TETL_VERSION_STRING "0.4.0"

#if defined(__STDC_HOSTED__)
    #define TETL_HOSTED 1
#else
    #define TETL_FREESTANDING 1
#endif

#endif // TETL_CONFIG_VERSION_HPP
