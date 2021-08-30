/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTDINT_UINT_T_HPP
#define TETL_CSTDINT_UINT_T_HPP

#include "etl/_config/all.hpp"

namespace etl {

/// \brief Unsigned integer type with width of exactly 8 bits.
using uint8_t = TETL_BUILTIN_UINT8;

/// \brief Unsigned integer type with width of exactly 16 bits.
using uint16_t = TETL_BUILTIN_UINT16;

/// \brief Unsigned integer type with width of exactly 32 bits.
using uint32_t = TETL_BUILTIN_UINT32;

/// \brief Unsigned integer type with width of exactly 64 bits.
using uint64_t = TETL_BUILTIN_UINT64;

} // namespace etl

static_assert(sizeof(etl::uint8_t) == 1, "uint8_t size should be 1");
static_assert(sizeof(etl::uint16_t) == 2, "uint16_t size should be 2");
static_assert(sizeof(etl::uint32_t) == 4, "uint32_t size should be 4");
static_assert(sizeof(etl::uint64_t) == 8, "uint64_t size should be 8");

#endif // TETL_CSTDINT_UINT_T_HPP