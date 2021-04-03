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

#ifndef TAETL_INTRINSICS_HPP
#define TAETL_INTRINSICS_HPP

#define TAETL_IS_ENUM(Type) __is_enum(Type)
#define TAETL_IS_CLASS(Type) __is_class(Type)
#define TAETL_IS_UNION(Type) __is_union(Type)

#define TAETL_IS_POLYMORPHIC(Type) __is_polymorphic(Type)
#define TAETL_IS_FINAL(Type) __is_final(Type)
#define TAETL_IS_ABSTRACT(Type) __is_abstract(Type)

#define TAETL_IS_AGGREGATE(Type) __is_aggregate(Type)

#define TAETL_HAS_VIRTUAL_DESTRUCTOR(Type) __has_virtual_destructor(Type)

#define TAETL_IS_TRIVIAL_CONSTRUCTIBLE(Type) __is_trivially_constructible(Type)

// Macro not available in GCC8.2
#if defined(__is_nothrow_constructible)
#define TAETL_IS_NOTHROW_CONSTRUCTIBLE(Type) __is_nothrow_constructible(Type)
#else
#define TAETL_IS_NOTHROW_CONSTRUCTIBLE(Type) true
#endif

#define TAETL_IS_TRIVIAL_DESTRUCTIBLE(Type) __has_trivial_destructor(Type)

#define TAETL_IS_ASSIGNABLE(T, Arg) __is_assignable(T, Arg)
#define TAETL_IS_TRIVIALLY_ASSIGNABLE(T, Arg) __is_trivially_assignable(T, Arg)

#define TAETL_IS_CONSTANT_EVALUATED() __builtin_is_constant_evaluated()

#define TAETL_BUILTIN_NAN (__builtin_nanf(""))
#define TAETL_BUILTIN_INFINITY (__builtin_inff())

#ifdef _MSC_VER
#define TAETL_BUILTIN_INT8 __int8
#define TAETL_BUILTIN_INT16 __int16
#define TAETL_BUILTIN_INT32 __int32
#define TAETL_BUILTIN_INT64 __int64
#define TAETL_BUILTIN_UINT8 unsigned __int8
#define TAETL_BUILTIN_UINT16 unsigned __int16
#define TAETL_BUILTIN_UINT32 unsigned __int32
#define TAETL_BUILTIN_UINT64 unsigned __int64

#define TAETL_BUILTIN_INTPTR TAETL_BUILTIN_INT64
#define TAETL_BUILTIN_UINTPTR TAETL_BUILTIN_UINT64
#define TAETL_BUILTIN_INTMAX TAETL_BUILTIN_INT64
#define TAETL_BUILTIN_UINTMAX TAETL_BUILTIN_UINT64
#define TAETL_BUILTIN_SIZET decltype(sizeof(nullptr))
#define TAETL_BUILTIN_PTRDIFF TAETL_BUILTIN_INT64
#else
#define TAETL_BUILTIN_INT8 __INT8_TYPE__
#define TAETL_BUILTIN_INT16 __INT16_TYPE__
#define TAETL_BUILTIN_INT32 __INT32_TYPE__
#define TAETL_BUILTIN_INT64 __INT64_TYPE__
#define TAETL_BUILTIN_UINT8 __UINT8_TYPE__
#define TAETL_BUILTIN_UINT16 __UINT16_TYPE__
#define TAETL_BUILTIN_UINT32 __UINT32_TYPE__
#define TAETL_BUILTIN_UINT64 __UINT64_TYPE__

#define TAETL_BUILTIN_INTPTR __INTPTR_TYPE__
#define TAETL_BUILTIN_UINTPTR __UINTPTR_TYPE__
#define TAETL_BUILTIN_INTMAX __INTMAX_TYPE__
#define TAETL_BUILTIN_UINTMAX __UINTMAX_TYPE__
#define TAETL_BUILTIN_SIZET __SIZE_TYPE__
#define TAETL_BUILTIN_PTRDIFF __PTRDIFF_TYPE__
#endif

// Resolve which function signature macro will be used.
#if defined(__GNUC__) || (defined(__MWERKS__) && (__MWERKS__ >= 0x3000))       \
  || (defined(__ICC) && (__ICC >= 600)) || defined(__ghs__)
#define TAETL_FUNC_SIG __PRETTY_FUNCTION__
#elif defined(__DMC__) && (__DMC__ >= 0x810)
#define TAETL_FUNC_SIG __PRETTY_FUNCTION__
#elif defined(__FUNCSIG__)
#define TAETL_FUNC_SIG __FUNCSIG__
#elif (defined(__INTEL_COMPILER) && (__INTEL_COMPILER >= 600))                 \
  || (defined(__IBMCPP__) && (__IBMCPP__ >= 500))
#define TAETL_FUNC_SIG __FUNCTION__
#elif defined(__BORLANDC__) && (__BORLANDC__ >= 0x550)
#define TAETL_FUNC_SIG __FUNC__
#elif defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 199901)
#define TAETL_FUNC_SIG __func__
#elif defined(__cplusplus) && (__cplusplus >= 201103)
#define TAETL_FUNC_SIG __func__
#else
#error "TAETL_FUNC_SIG unknown!"
#endif

#endif  // TAETL_INTRINSICS_HPP