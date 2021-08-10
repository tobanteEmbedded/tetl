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

#ifndef TETL_CSTDINT_HPP
#define TETL_CSTDINT_HPP

/// \file This header was originally in the C standard library as <stdint.h>.
/// This header is part of the type support library, providing fixed width
/// integer types and part of C numeric limits interface.

#include "etl/version.hpp"

#include "etl/_cstdint/int_fast_t.hpp"
#include "etl/_cstdint/int_least_t.hpp"
#include "etl/_cstdint/int_t.hpp"
#include "etl/_cstdint/intmax_t.hpp"
#include "etl/_cstdint/intptr_t.hpp"
#include "etl/_cstdint/uint_fast_t.hpp"
#include "etl/_cstdint/uint_least_t.hpp"
#include "etl/_cstdint/uint_t.hpp"
#include "etl/_cstdint/uintmax_t.hpp"
#include "etl/_cstdint/uintptr_t.hpp"

static_assert(sizeof(::etl::int8_t) == 1, "int8_t size should be 1");
static_assert(sizeof(::etl::int16_t) == 2, "int16_t size should be 2");
static_assert(sizeof(::etl::int32_t) == 4, "int32_t size should be 4");
static_assert(sizeof(::etl::int64_t) == 8, "int64_t size should be 8");

static_assert(sizeof(::etl::uint8_t) == 1, "uint8_t size should be 1");
static_assert(sizeof(::etl::uint16_t) == 2, "uint16_t size should be 2");
static_assert(sizeof(::etl::uint32_t) == 4, "uint32_t size should be 4");
static_assert(sizeof(::etl::uint64_t) == 8, "uint64_t size should be 8");

static_assert(sizeof(::etl::int_fast8_t) >= 1);
static_assert(sizeof(::etl::int_fast16_t) >= 2);
static_assert(sizeof(::etl::int_fast32_t) >= 4);
static_assert(sizeof(::etl::int_fast64_t) >= 8);

static_assert(sizeof(::etl::uint_fast8_t) >= 1);
static_assert(sizeof(::etl::uint_fast16_t) >= 2);
static_assert(sizeof(::etl::uint_fast32_t) >= 4);
static_assert(sizeof(::etl::uint_fast64_t) >= 8);

static_assert(sizeof(::etl::int_least8_t) >= 1);
static_assert(sizeof(::etl::int_least16_t) >= 2);
static_assert(sizeof(::etl::int_least32_t) >= 4);
static_assert(sizeof(::etl::int_least64_t) >= 8);

static_assert(sizeof(::etl::uint_least8_t) >= 1);
static_assert(sizeof(::etl::uint_least16_t) >= 2);
static_assert(sizeof(::etl::uint_least32_t) >= 4);
static_assert(sizeof(::etl::uint_least64_t) >= 8);

#endif // TETL_CSTDINT_HPP