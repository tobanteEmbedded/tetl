/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_DEFINITONS_HPP
#define TAETL_DEFINITONS_HPP

#include "version.hpp"

#include <stddef.h>
#include <stdint.h>

#ifdef abs
#undef abs
#endif

/**
 * @brief Namespace for the etl library.
 */
namespace etl
{
using int8_t = int8_t;
static_assert(sizeof(etl::int8_t) == 1, "int8 size should be 1");

using int16_t = int16_t;
static_assert(sizeof(etl::int16_t) == 2, "int16 size should be 2");

using int32_t = int32_t;
static_assert(sizeof(etl::int32_t) == 4, "int32 size should be 4");

using int64_t = int64_t;
static_assert(sizeof(etl::int64_t) == 8, "int64 size should be 8");

using uint8_t = uint8_t;
static_assert(sizeof(etl::uint8_t) == 1, "uint8 size should be 1");

using uint16_t = uint16_t;
static_assert(sizeof(etl::uint16_t) == 2, "uint16 size should be 2");

using uint32_t = uint32_t;
static_assert(sizeof(etl::uint32_t) == 4, "uint32 size should be 4");

using uint64_t = uint64_t;
static_assert(sizeof(etl::uint64_t) == 8, "uint64 size should be 8");

using intptr_t  = intptr_t;
using uintptr_t = uintptr_t;
using intmax_t  = intmax_t;
using uintmax_t = uintmax_t;
using size_t    = size_t;
using ptrdiff_t = ptrdiff_t;
using nullptr_t = decltype(nullptr);

struct alignas(long double) max_align_t
{
};

}  // namespace etl
#endif  // TAETL_DEFINITONS_HPP
