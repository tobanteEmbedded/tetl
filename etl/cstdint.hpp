/*
Copyright (c) Tobias Hienzsch. All rights reserved.

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

#ifndef TAETL_CSTDINT_HPP
#define TAETL_CSTDINT_HPP

#include "etl/version.hpp"

#include "etl/detail/intrinsics.hpp"

namespace etl
{
using int8_t = TAETL_BUILTIN_INT8;
static_assert(sizeof(etl::int8_t) == 1, "int8 size should be 1");

using int16_t = TAETL_BUILTIN_INT16;
static_assert(sizeof(etl::int16_t) == 2, "int16 size should be 2");

using int32_t = TAETL_BUILTIN_INT32;
static_assert(sizeof(etl::int32_t) == 4, "int32 size should be 4");

using int64_t = TAETL_BUILTIN_INT64;
static_assert(sizeof(etl::int64_t) == 8, "int64 size should be 8");

using uint8_t = TAETL_BUILTIN_UINT8;
static_assert(sizeof(etl::uint8_t) == 1, "uint8 size should be 1");

using uint16_t = TAETL_BUILTIN_UINT16;
static_assert(sizeof(etl::uint16_t) == 2, "uint16 size should be 2");

using uint32_t = TAETL_BUILTIN_UINT32;
static_assert(sizeof(etl::uint32_t) == 4, "uint32 size should be 4");

using uint64_t = TAETL_BUILTIN_UINT64;
static_assert(sizeof(etl::uint64_t) == 8, "uint64 size should be 8");

using intptr_t  = TAETL_BUILTIN_INTPTR;
using uintptr_t = TAETL_BUILTIN_UINTPTR;
using intmax_t  = TAETL_BUILTIN_INTMAX;
using uintmax_t = TAETL_BUILTIN_UINTMAX;

}  // namespace etl

#endif  // TAETL_CSTDINT_HPP