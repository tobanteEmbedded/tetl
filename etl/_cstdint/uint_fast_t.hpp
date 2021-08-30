/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTDINT_UINT_FAST_T_HPP
#define TETL_CSTDINT_UINT_FAST_T_HPP

#include "etl/_config/all.hpp"

namespace etl {

/// \brief Signed integer type with width of at least 8 bits.
using uint_fast8_t = TETL_BUILTIN_UINT8;

/// \brief Signed integer type with width of at least 16 bits.
using uint_fast16_t = TETL_BUILTIN_UINT16;

/// \brief Signed integer type with width of at least 32 bits.
using uint_fast32_t = TETL_BUILTIN_UINT32;

/// \brief Signed integer type with width of at least 64 bits.
using uint_fast64_t = TETL_BUILTIN_UINT64;

} // namespace etl

static_assert(sizeof(etl::uint_fast8_t) >= 1);
static_assert(sizeof(etl::uint_fast16_t) >= 2);
static_assert(sizeof(etl::uint_fast32_t) >= 4);
static_assert(sizeof(etl::uint_fast64_t) >= 8);

#endif // TETL_CSTDINT_UINT_FAST_T_HPP