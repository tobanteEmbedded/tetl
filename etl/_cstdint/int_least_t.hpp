// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_CSTDINT_INT_LEAST_T_HPP
#define TETL_CSTDINT_INT_LEAST_T_HPP

#include "etl/_config/builtin_types.hpp"

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