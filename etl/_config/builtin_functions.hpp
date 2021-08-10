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

#ifndef TETL_CONFIG_BUILTIN_FUNCTIONS_HPP
#define TETL_CONFIG_BUILTIN_FUNCTIONS_HPP

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

#if __has_builtin(__builtin_unreachable)
#define TETL_BUILTIN_UNREACHABLE __builtin_unreachable()
#elif defined(_MSC_VER)
#define TETL_BUILTIN_UNREACHABLE __assume(false)
#else
// https://stackoverflow.com/questions/6031819/emulating-gccs-builtin-unreachable
// Answer from user iammilind.
#define TETL_BUILTIN_UNREACHABLE                                               \
    {                                                                          \
        struct etl_builtin_unreachable_t {                                     \
            etl_builtin_unreachable_t& operator=(                              \
                etl_builtin_unreachable_t const&);                             \
        } x;                                                                   \
        x = x;                                                                 \
    }
#endif

#if __has_builtin(__builtin_expect)
#define TETL_LIKELY(EXPR) __builtin_expect(static_cast<bool>(EXPR), true)
#define TETL_UNLIKELY(EXPR) __builtin_expect(static_cast<bool>(EXPR), false)
#else
#define TETL_LIKELY(EXPR) (EXPR)
#define TETL_UNLIKELY(EXPR) (EXPR)
#endif

#if not defined(TETL_BUILTIN_NANF)
#define TETL_BUILTIN_NANF(x) __builtin_nanf((x))
#endif

#if not defined(TETL_BUILTIN_SIGNAL_NANF)
#define TETL_BUILTIN_SIGNAL_NANF(x) __builtin_nansf((x))
#endif

#if not defined(TETL_BUILTIN_NAN)
#define TETL_BUILTIN_NAN(x) __builtin_nan((x))
#endif

#if not defined(TETL_BUILTIN_SIGNAL_NAN)
#define TETL_BUILTIN_SIGNAL_NAN(x) __builtin_nans((x))
#endif

#if not defined(TETL_BUILTIN_HUGE_VALF)
#define TETL_BUILTIN_HUGE_VALF (__builtin_huge_valf())
#endif

#if not defined(TETL_BUILTIN_HUGE_VAL)
#define TETL_BUILTIN_HUGE_VAL (__builtin_huge_val())
#endif

#if not defined(TETL_BUILTIN_HUGE_VALL)
#define TETL_BUILTIN_HUGE_VALL (__builtin_huge_vall())
#endif

#if not defined(TETL_BUILTIN_VA_LIST)
#define TETL_BUILTIN_VA_LIST __builtin_va_list
#endif // TETL_BUILTIN_VA_LIST

#if __has_builtin(__builtin_assume_aligned)
#define TETL_BUILTIN_ASSUME_ALIGNED(p, a) __builtin_assume_aligned(p, a)
#else
#define TETL_BUILTIN_ASSUME_ALIGNED(p, a) (p)
#endif

#if __has_builtin(__builtin_signbit) && !defined(TETL_CLANG)
#define TETL_BUILTIN_SIGNBIT(x) __builtin_signbit(x)
#else
#define TETL_BUILTIN_SIGNBIT(x) ::etl::detail::builtin_signbit_fallback(x)
#endif

#if __has_builtin(__builtin_copysign)
#define TETL_BUILTIN_COPYSIGN(x, y) __builtin_copysign(x, y)
#else
#define TETL_BUILTIN_COPYSIGN(x, y)                                            \
    ::etl::detail::builtin_copysign_fallback(x, y)
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

namespace etl::detail {
template <typename T>
constexpr auto builtin_copysign_fallback(T x, T y) noexcept -> T
{
    if ((x < 0 && y > 0) || (x > 0 && y < 0)) { return -x; }
    return x;
}

template <typename T>
constexpr auto builtin_signbit_fallback(T arg) noexcept -> bool
{
    return arg == T(-0.0) || arg < T(0);
}
} // namespace etl::detail

#endif // TETL_CONFIG_BUILTIN_FUNCTIONS_HPP