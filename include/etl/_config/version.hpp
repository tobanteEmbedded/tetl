// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CONFIG_VERSION_HPP
#define TETL_CONFIG_VERSION_HPP

/// \brief The major release version
// NOLINTNEXTLINE(modernize-macro-to-enum)
#define TETL_VERSION_MAJOR 0

/// \brief The minor release version
// NOLINTNEXTLINE(modernize-macro-to-enum)
#define TETL_VERSION_MINOR 1

/// \brief The patch release version
// NOLINTNEXTLINE(modernize-macro-to-enum)
#define TETL_VERSION_PATCH 0

/// \brief The library version as a string literal
#define TETL_VERSION_STRING "0.1.0"

#if defined(__STDC_HOSTED__)
    #define TETL_HOSTED
#else
    #define TETL_FREESTANDING
#endif

#endif // TETL_CONFIG_VERSION_HPP
