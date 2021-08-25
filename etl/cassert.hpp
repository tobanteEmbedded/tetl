/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CASSERT_HPP
#define TETL_CASSERT_HPP

/// \file This header is part of the error handling library.
/// \example cassert.cpp

#include "etl/_config/all.hpp"

#include "etl/_assert/macro.hpp"

#if __has_include(<assert.h>)
#include <assert.h>
#else
#ifndef assert
#define assert(x) TETL_ASSERT(x)
#endif
#endif

#endif // TETL_CASSERT_HPP
