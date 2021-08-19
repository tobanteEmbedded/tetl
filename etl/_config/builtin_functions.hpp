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
#define TETL_LIKELY(expr) __builtin_expect(static_cast<bool>(expr), true)
#define TETL_UNLIKELY(expr) __builtin_expect(static_cast<bool>(expr), false)
#else
#define TETL_LIKELY(expr) (expr)
#define TETL_UNLIKELY(expr) (expr)
#endif

#if not defined(TETL_BUILTIN_NANF)
#if __has_builtin(__builtin_nanf) or defined(_MSC_VER)
#define TETL_BUILTIN_NANF (__builtin_nanf(""))
#else
#define TETL_BUILTIN_NANF (0.0F / 0.0F)
#endif
#endif

#if not defined(TETL_BUILTIN_NAN)
#if __has_builtin(__builtin_nan) or defined(_MSC_VER)
#define TETL_BUILTIN_NAN (__builtin_nan(""))
#else
#define TETL_BUILTIN_NAN (0.0 / 0.0)
#endif
#endif

#if not defined(TETL_BUILTIN_NANL)
#if __has_builtin(__builtin_nanl) or defined(_MSC_VER)
#define TETL_BUILTIN_NANL (__builtin_nanl(""))
#elif defined(_MSC_VER)
#define TETL_BUILTIN_NANL (__builtin_nan(""))
#else
#define TETL_BUILTIN_NANL (0.0L / 0.0L)
#endif
#endif

#if not defined(TETL_BUILTIN_NANSF)
#if __has_builtin(__builtin_nansf) or defined(_MSC_VER)
#define TETL_BUILTIN_NANSF (__builtin_nansf(""))
#else
#define TETL_BUILTIN_NANSF (0.0F / 0.0F)
#endif
#endif

#if not defined(TETL_BUILTIN_NANS)
#if __has_builtin(__builtin_nans) or defined(_MSC_VER)
#define TETL_BUILTIN_NANS (__builtin_nans(""))
#else
#define TETL_BUILTIN_NANS (0.0 / 0.0)
#endif
#endif

#if not defined(TETL_BUILTIN_NANSL)
#if __has_builtin(__builtin_nansl)
#define TETL_BUILTIN_NANSL (__builtin_nansl(""))
#elif defined(_MSC_VER)
#define TETL_BUILTIN_NANSL (__builtin_nans(""))
#else
#define TETL_BUILTIN_NANSL (0.0L / 0.0L)
#endif
#endif

#if not defined(TETL_BUILTIN_HUGE_VALF)
#if __has_builtin(__builtin_huge_valf) or defined(_MSC_VER)
#define TETL_BUILTIN_HUGE_VALF (__builtin_huge_valf())
#else
#define TETL_BUILTIN_HUGE_VALF (1.0F / 0.0F)
#endif
#endif

#if not defined(TETL_BUILTIN_HUGE_VAL)
#if __has_builtin(__builtin_huge_val) or defined(_MSC_VER)
#define TETL_BUILTIN_HUGE_VAL (__builtin_huge_val())
#else
#define TETL_BUILTIN_HUGE_VAL (1.0 / 0.0)
#endif
#endif

#if not defined(TETL_BUILTIN_HUGE_VALL)
#if __has_builtin(__builtin_huge_vall)
#define TETL_BUILTIN_HUGE_VALL (__builtin_huge_vall())
#elif defined(_MSC_VER)
#define TETL_BUILTIN_HUGE_VALL (__builtin_huge_val())
#else
#define TETL_BUILTIN_HUGE_VALL (1.0L / 0.0L)
#endif
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

#if __has_builtin(__builtin_copysignf)
#define TETL_BUILTIN_COPYSIGNF(x, y) __builtin_copysignf(x, y)
#else
#define TETL_BUILTIN_COPYSIGNF(x, y)                                           \
    ::etl::detail::builtin_copysign_fallback(x, y)
#endif

#if __has_builtin(__builtin_copysignl)
#define TETL_BUILTIN_COPYSIGNL(x, y) __builtin_copysignl(x, y)
#else
#define TETL_BUILTIN_COPYSIGNL(x, y)                                           \
    ::etl::detail::builtin_copysign_fallback(x, y)
#endif

#if __has_builtin(__builtin_addressof)
#define TETL_BUILTIN_ADDRESSOF(x) __builtin_addressof(x)
#else
#define TETL_BUILTIN_ADDRESSOF(x) ::etl::detail::builtin_addressof_fallback(x)
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

template <typename T>
auto builtin_addressof_fallback(T& arg) noexcept -> T*
{
    return reinterpret_cast<T*>(
        &const_cast<char&>(reinterpret_cast<const volatile char&>(arg)));
}

} // namespace etl::detail

#endif // TETL_CONFIG_BUILTIN_FUNCTIONS_HPP