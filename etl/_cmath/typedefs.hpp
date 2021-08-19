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

#ifndef TETL_CMATH_TYPEDEFS_HPP
#define TETL_CMATH_TYPEDEFS_HPP

#include "etl/_config/builtin_functions.hpp"

#if not defined(_MSC_VER)

#ifndef NAN
#define NAN TETL_BUILTIN_NAN("")
#endif

#ifndef INFINITY
#define INFINITY TETL_BUILTIN_HUGE_VALF
#endif

#ifndef HUGE_VALF
#define HUGE_VALF TETL_BUILTIN_HUGE_VALF
#endif

#ifndef HUGE_VAL
#define HUGE_VAL TETL_BUILTIN_HUGE_VAL
#endif

#ifndef HUGE_VALL
#define HUGE_VALL TETL_BUILTIN_HUGE_VALL
#endif

#endif // not defined(_MSC_VER)

namespace etl {
/// \brief Most efficient floating-point type at least as wide as float.
using float_t = float;

/// \brief Most efficient floating-point type at least as wide as double.
using double_t = double;
} // namespace etl

#endif // TETL_CMATH_TYPEDEFS_HPP