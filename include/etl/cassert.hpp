// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CASSERT_HPP
#define TETL_CASSERT_HPP

/// \file This header is part of the error handling library.
/// \example cassert.cpp

#include <etl/_config/all.hpp>

#include <etl/_cassert/macro.hpp>

#ifndef assert
    #define assert(...) TETL_ASSERT(__VA_ARGS__)
#endif

#endif // TETL_CASSERT_HPP
