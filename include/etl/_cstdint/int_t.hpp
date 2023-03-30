// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTDINT_INT_T_HPP
#define TETL_CSTDINT_INT_T_HPP

#include "etl/_config/all.hpp"

namespace etl {

/// \brief Signed integer type with width of exactly 8 bits.
using int8_t = TETL_BUILTIN_INT8;

/// \brief Signed integer type with width of exactly 16 bits.
using int16_t = TETL_BUILTIN_INT16;

/// \brief Signed integer type with width of exactly 32 bits.
using int32_t = TETL_BUILTIN_INT32;

/// \brief Signed integer type with width of exactly 64 bits.
using int64_t = TETL_BUILTIN_INT64;

} // namespace etl

static_assert(sizeof(etl::int8_t) == 1, "int8_t size should be 1");
static_assert(sizeof(etl::int16_t) == 2, "int16_t size should be 2");
static_assert(sizeof(etl::int32_t) == 4, "int32_t size should be 4");
static_assert(sizeof(etl::int64_t) == 8, "int64_t size should be 8");

#endif // TETL_CSTDINT_INT_T_HPP
