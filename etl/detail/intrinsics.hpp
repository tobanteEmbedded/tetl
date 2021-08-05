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

#ifndef TETL_INTRINSICS_HPP
#define TETL_INTRINSICS_HPP

#if defined(__clang__)
#define TETL_CLANG 1
#elif defined(__GNUC__)
#define TETL_GCC 1
#elif defined(_MSC_VER)
#define TETL_MSVC 1
#elif defined(__INTEL_COMPILER)
#define TETL_INTEL 1
#elif defined(__EMSCRIPTEN__)
#define TETL_EMSCRIPTEN 1
#else
#error "unknown compiler"
#endif

#if defined(__GNUC__)
#define TETL_FUNC_SIG __PRETTY_FUNCTION__
#else
#define TETL_FUNC_SIG __func__
#endif

#if not defined(TETL_BUILTIN_NAN)
#define TETL_BUILTIN_NAN (__builtin_nanf(""))
#endif // TETL_BUILTIN_NAN

#if not defined(TETL_BUILTIN_INFINITY)
#define TETL_BUILTIN_INFINITY (__builtin_inff())
#endif // TETL_BUILTIN_INFINITY

#if not defined(TETL_BUILTIN_VA_LIST)
#define TETL_BUILTIN_VA_LIST __builtin_va_list
#endif // TETL_BUILTIN_VA_LIST

#if not defined(TETL_HAS_VIRTUAL_DESTRUCTOR)
#define TETL_HAS_VIRTUAL_DESTRUCTOR(Type) __has_virtual_destructor(Type)
#endif // TETL_HAS_VIRTUAL_DESTRUCTOR

#if not defined(TETL_HAS_UNIQUE_OBJECT_REPRESENTATION)
#define TETL_HAS_UNIQUE_OBJECT_REPRESENTATION(Type)                            \
    __has_unique_object_representations(Type)
#endif // TETL_HAS_UNIQUE_OBJECT_REPRESENTATION

#if not defined(TETL_IS_ABSTRACT)
#define TETL_IS_ABSTRACT(Type) __is_abstract(Type)
#endif // TETL_IS_ABSTRACT

#if not defined(TETL_IS_AGGREGATE)
#define TETL_IS_AGGREGATE(Type) __is_aggregate(Type)
#endif // TETL_IS_AGGREGATE

#if not defined(TETL_IS_ASSIGNABLE)
#define TETL_IS_ASSIGNABLE(Type, Arg) __is_assignable(Type, Arg)
#endif // TETL_IS_ASSIGNABLE

#if not defined(TETL_IS_CONSTANT_EVALUATED)
#define TETL_IS_CONSTANT_EVALUATED() __builtin_is_constant_evaluated()
#endif // TETL_IS_CONSTANT_EVALUATED

#if not defined(TETL_IS_CONSTRUCTIBLE)
#define TETL_IS_CONSTRUCTIBLE(Type, Args) __is_constructible(Type, Args)
#endif // TETL_IS_CONSTRUCTIBLE

#if not defined(TETL_IS_CLASS)
#define TETL_IS_CLASS(Type) __is_class(Type)
#endif // TETL_IS_CLASS

#if not defined(TETL_IS_ENUM)
#define TETL_IS_ENUM(Type) __is_enum(Type)
#endif // TETL_IS_ENUM

#if not defined(TETL_IS_FINAL)
#define TETL_IS_FINAL(Type) __is_final(Type)
#endif // TETL_IS_FINAL

#if not defined(TETL_IS_POLYMORPHIC)
#define TETL_IS_POLYMORPHIC(Type) __is_polymorphic(Type)
#endif // TETL_IS_POLYMORPHIC

#if not defined(TETL_IS_STANDARD_LAYOUT)
#define TETL_IS_STANDARD_LAYOUT(Type) __is_standard_layout(Type)
#endif // TETL_IS_STANDARD_LAYOUT

#if not defined(TETL_IS_TRIVIALLY_ASSIGNABLE)
#define TETL_IS_TRIVIALLY_ASSIGNABLE(T, Arg) __is_trivially_assignable(T, Arg)
#endif // TETL_IS_TRIVIALLY_ASSIGNABLE

#if not defined(TETL_IS_TRIVIAL_CONSTRUCTIBLE)
#define TETL_IS_TRIVIAL_CONSTRUCTIBLE(Type) __is_trivially_constructible(Type)
#endif // TETL_IS_TRIVIAL_CONSTRUCTIBLE

#if not defined(TETL_IS_TRIVIAL_DESTRUCTIBLE)
#define TETL_IS_TRIVIAL_DESTRUCTIBLE(Type) __has_trivial_destructor(Type)
#endif // TETL_IS_TRIVIAL_DESTRUCTIBLE

#if not defined(TETL_IS_UNION)
#define TETL_IS_UNION(Type) __is_union(Type)
#endif // TETL_IS_UNION

#if not defined(TETL_IS_UNDERLYING_TYPE)
#define TETL_IS_UNDERLYING_TYPE(Type) __underlying_type(Type)
#endif // TETL_IS_UNDERLYING_TYPE

#if not defined(TETL_MAKE_INTEGER_SEQ)
#if defined(TETL_CLANG) or defined(TETL_MSVC)
#define TETL_MAKE_INTEGER_SEQ(T, N) __make_integer_seq<integer_sequence, T, N>
#else
#define TETL_MAKE_INTEGER_SEQ(T, N) integer_sequence<T, __integer_pack(N)...>
#endif
#endif // TETL_MAKE_INTEGER_SEQ

#ifdef _MSC_VER
#define TETL_BUILTIN_INT8 __int8
#define TETL_BUILTIN_INT16 __int16
#define TETL_BUILTIN_INT32 __int32
#define TETL_BUILTIN_INT64 __int64
#define TETL_BUILTIN_UINT8 unsigned __int8
#define TETL_BUILTIN_UINT16 unsigned __int16
#define TETL_BUILTIN_UINT32 unsigned __int32
#define TETL_BUILTIN_UINT64 unsigned __int64

#define TETL_BUILTIN_INTPTR TETL_BUILTIN_INT64
#define TETL_BUILTIN_UINTPTR TETL_BUILTIN_UINT64
#define TETL_BUILTIN_INTMAX TETL_BUILTIN_INT64
#define TETL_BUILTIN_UINTMAX TETL_BUILTIN_UINT64
#define TETL_BUILTIN_SIZET decltype(sizeof(nullptr))
#define TETL_BUILTIN_PTRDIFF TETL_BUILTIN_INT64
#else
#define TETL_BUILTIN_INT8 __INT8_TYPE__
#define TETL_BUILTIN_INT16 __INT16_TYPE__
#define TETL_BUILTIN_INT32 __INT32_TYPE__
#define TETL_BUILTIN_INT64 __INT64_TYPE__
#define TETL_BUILTIN_UINT8 __UINT8_TYPE__
#define TETL_BUILTIN_UINT16 __UINT16_TYPE__
#define TETL_BUILTIN_UINT32 __UINT32_TYPE__
#define TETL_BUILTIN_UINT64 __UINT64_TYPE__

#define TETL_BUILTIN_INTPTR __INTPTR_TYPE__
#define TETL_BUILTIN_UINTPTR __UINTPTR_TYPE__
#define TETL_BUILTIN_INTMAX __INTMAX_TYPE__
#define TETL_BUILTIN_UINTMAX __UINTMAX_TYPE__
#define TETL_BUILTIN_SIZET __SIZE_TYPE__
#define TETL_BUILTIN_PTRDIFF __PTRDIFF_TYPE__
#endif

#endif // TETL_INTRINSICS_HPP