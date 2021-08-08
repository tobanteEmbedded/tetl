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

#ifndef __has_feature
#define __has_feature(x) 0
#endif

#ifndef __has_extension
#define __has_extension(x) 0
#endif

#ifndef __has_attribute
#define __has_attribute(x) 0
#endif

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

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

#define TETL_STRINGIFY_IMPL(str) #str
#define TETL_STRINGIFY(str) TETL_STRINGIFY_IMPL(str)

#define TETL_CONCAT_IMPL(s1, s2) s1##s2
#define TETL_CONCAT(s1, s2) TETL_CONCAT_IMPL(s1, s2)

#ifdef __COUNTER__
#define TETL_ANONYMOUS_VAR(name) TETL_CONCAT(name, __COUNTER__)
#else
#define TETL_ANONYMOUS_VAR(name) TETL_CONCAT(name, __LINE__)
#endif

#if defined(__GNUC__)
#define TETL_FUNC_SIG __PRETTY_FUNCTION__
#else
#define TETL_FUNC_SIG __func__
#endif

#if __has_builtin(__builtin_COLUMN)
#define TETL_BUILTIN_COLUMN() __builtin_COLUMN()
#else
#define TETL_BUILTIN_COLUMN() 0
#endif

#if __has_builtin(__builtin_LINE)
#define TETL_BUILTIN_LINE() __builtin_LINE()
#else
#define TETL_BUILTIN_LINE() 0
#endif

#if __has_builtin(__builtin_FILE)
#define TETL_BUILTIN_FILE() __builtin_FILE()
#else
#define TETL_BUILTIN_FILE() __FILE__
#endif

#if __has_builtin(__builtin_FUNCTION)
#define TETL_BUILTIN_FUNCTION() __builtin_FUNCTION()
#else
#define TETL_BUILTIN_FUNCTION() ""
#endif

#if defined(__cpp_consteval)
#define TETL_CONSTEVAL consteval
#else
#define TETL_CONSTEVAL constexpr
#endif

#if __has_builtin(__builtin_expect)
#define TETL_LIKELY(EXPR) __builtin_expect(static_cast<bool>(EXPR), true)
#define TETL_UNLIKELY(EXPR) __builtin_expect(static_cast<bool>(EXPR), false)
#else
#define TETL_LIKELY(EXPR) (EXPR)
#define TETL_UNLIKELY(EXPR) (EXPR)
#endif

#if __has_attribute(always_inline)
#define TETL_ALWAYS_INLINE __attribute__((always_inline))
#elif defined(_MSC_VER)
#define TETL_ALWAYS_INLINE __forceinline
#else
#define TETL_ALWAYS_INLINE
#endif

#ifdef __GNUC__
#define TETL_NORETURN __attribute__((noreturn))
#elif defined(_MSC_VER)
#define TETL_NORETURN __declspec(noreturn)
#else
#define TETL_NORETURN
#endif

#if __has_builtin(__builtin_unreachable)
#define TETL_BUILTIN_UNREACHABLE __builtin_unreachable()
#elif defined(_MSC_VER)
#define TETL_BUILTIN_UNREACHABLE __assume(false)
#endif

#if __has_builtin(__builtin_nanf) || defined(_MSC_VER)
#define TETL_BUILTIN_NANF(x) __builtin_nanf((x))
#else
#error "No builtin for NANs"
#endif

#if __has_builtin(__builtin_nansf) || defined(_MSC_VER)
#define TETL_BUILTIN_SIGNAL_NANF(x) __builtin_nansf((x))
#else
#error "No builtin for signal NANs"
#endif

#if __has_builtin(__builtin_nan) || defined(_MSC_VER)
#define TETL_BUILTIN_NAN(x) __builtin_nan((x))
#else
#error "No builtin for NANs"
#endif

#if __has_builtin(__builtin_nans) || defined(_MSC_VER)
#define TETL_BUILTIN_SIGNAL_NAN(x) __builtin_nans((x))
#else
#error "No builtin for signal NANs"
#endif

#if __has_builtin(__builtin_inff)
#define TETL_BUILTIN_INFINITY (__builtin_inff())
#elif __has_builtin(__builtin_huge_valf) || defined(_MSC_VER)
#define TETL_BUILTIN_INFINITY (__builtin_huge_valf(()))
#else
#error "No builtin for infinity"
#endif

#if not defined(TETL_BUILTIN_VA_LIST)
#define TETL_BUILTIN_VA_LIST __builtin_va_list
#endif // TETL_BUILTIN_VA_LIST

#if __has_builtin(__builtin_assume_aligned)
#define TETL_BUILTIN_ASSUME_ALIGNED(p, a) __builtin_assume_aligned(p, a)
#elif defined(TETL_BUILTIN_UNREACHABLE)
#define TETL_BUILTIN_ASSUME_ALIGNED(p, a)                                      \
    (((reinterpret_cast<TETL_BUILTIN_UINTPTR>(p) % (a)) == 0)                  \
            ? (p)                                                              \
            : (TETL_BUILTIN_UNREACHABLE, (p)))
#else
#define TETL_BUILTIN_ASSUME_ALIGNED(p, a) (p)
#endif

#if __has_builtin(__builtin_is_constant_evaluated)
#define TETL_IS_CONSTANT_EVALUATED() __builtin_is_constant_evaluated()
#else
#define TETL_IS_CONSTANT_EVALUATED() false
#endif

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

#endif // TETL_INTRINSICS_HPP