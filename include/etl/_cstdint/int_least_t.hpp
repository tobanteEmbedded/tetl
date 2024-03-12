// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTDINT_INT_LEAST_T_HPP
#define TETL_CSTDINT_INT_LEAST_T_HPP

#include <etl/_config/all.hpp>

namespace etl {

/// \brief Signed integer type with width of at least 8 bits.
using int_least8_t = TETL_BUILTIN_INT8;

/// \brief Signed integer type with width of at least 16 bits.
using int_least16_t = TETL_BUILTIN_INT16;

/// \brief Signed integer type with width of at least 32 bits.
using int_least32_t = TETL_BUILTIN_INT32;

/// \brief Signed integer type with width of at least 64 bits.
using int_least64_t = TETL_BUILTIN_INT64;

} // namespace etl

static_assert(sizeof(etl::int_least8_t) >= 1);
static_assert(sizeof(etl::int_least16_t) >= 2);
static_assert(sizeof(etl::int_least32_t) >= 4);
static_assert(sizeof(etl::int_least64_t) >= 8);

#endif // TETL_CSTDINT_INT_LEAST_T_HPP
