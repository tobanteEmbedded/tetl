// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CASSERT_HPP
#define TETL_CASSERT_HPP

/// \defgroup cassert cassert.hpp
/// Conditionally compiled macro that compares its argument to zero
/// \ingroup errors-library
/// \example cassert.cpp
/// \code
/// #include <etl/cassert.hpp>
/// \endcode

#include <etl/_config/all.hpp>

#include <etl/_cassert/macro.hpp>

#ifndef assert
    #define assert(...) TETL_ASSERT(__VA_ARGS__)
#endif

#endif // TETL_CASSERT_HPP
