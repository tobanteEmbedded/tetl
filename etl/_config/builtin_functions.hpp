/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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

// UNREACHABLE
#if __has_builtin(__builtin_unreachable)
    #define TETL_BUILTIN_UNREACHABLE __builtin_unreachable()
#elif defined(TETL_MSVC)
    #define TETL_BUILTIN_UNREACHABLE __assume(false)
#else
    // https://stackoverflow.com/questions/6031819/emulating-gccs-builtin-unreachable
    // Answer from user iammilind.
    #define TETL_BUILTIN_UNREACHABLE                                           \
        {                                                                      \
            struct etl_builtin_unreachable_t {                                 \
                etl_builtin_unreachable_t& operator=(                          \
                    etl_builtin_unreachable_t const&);                         \
            } x;                                                               \
            x = x;                                                             \
        }
#endif

// NAN
#if __has_builtin(__builtin_nanf) or defined(TETL_MSVC) or defined(TETL_GCC)
    #define TETL_BUILTIN_NANF(arg) (__builtin_nanf(arg))
#else
    #define TETL_BUILTIN_NANF(arg) (0.0F / 0.0F)
#endif

#if __has_builtin(__builtin_nan) or defined(TETL_MSVC) or defined(TETL_GCC)
    #define TETL_BUILTIN_NAN(arg) (__builtin_nan(arg))
#else
    #define TETL_BUILTIN_NAN (0.0 / 0.0)
#endif

#if __has_builtin(__builtin_nanl) or defined(TETL_GCC)
    #define TETL_BUILTIN_NANL(arg) (__builtin_nanl(arg))
#elif defined(TETL_MSVC)
    #define TETL_BUILTIN_NANL(arg) (__builtin_nan(arg))
#else
    #define TETL_BUILTIN_NANL(arg) (0.0L / 0.0L)
#endif

// SIGNALING NAN
#if __has_builtin(__builtin_nansf) or defined(TETL_MSVC) or defined(TETL_GCC)
    #define TETL_BUILTIN_NANSF(arg) (__builtin_nansf(arg))
#else
    #define TETL_BUILTIN_NANSF(arg) (0.0F / 0.0F)
#endif

#if __has_builtin(__builtin_nans) or defined(TETL_MSVC) or defined(TETL_GCC)
    #define TETL_BUILTIN_NANS(arg) (__builtin_nans(arg))
#else
    #define TETL_BUILTIN_NANS(arg) (0.0 / 0.0)
#endif

#if __has_builtin(__builtin_nansl) or defined(TETL_GCC)
    #define TETL_BUILTIN_NANSL(arg) (__builtin_nansl(arg))
#elif defined(TETL_MSVC)
    #define TETL_BUILTIN_NANSL(arg) (__builtin_nans(arg))
#else
    #define TETL_BUILTIN_NANSL(arg) (0.0L / 0.0L)
#endif

// ISNAN
#if __has_builtin(__builtin_isnanf) or defined(TETL_GCC)
    #define TETL_BUILTIN_ISNANF(x) (__builtin_isnanf(x))
#else
    #define TETL_BUILTIN_ISNANF(x) (x != x)
#endif

#if __has_builtin(__builtin_isnan) or defined(TETL_GCC)
    #define TETL_BUILTIN_ISNAN(x) (__builtin_isnan(x))
#else
    #define TETL_BUILTIN_ISNAN(x) (x != x)
#endif

#if __has_builtin(__builtin_isnanl) or defined(TETL_GCC)
    #define TETL_BUILTIN_ISNANL(x) (__builtin_isnanl(x))
#else
    #define TETL_BUILTIN_ISNANL(x) (x != x)
#endif

// HUGE VAL
#if __has_builtin(__builtin_huge_valf) or defined(TETL_MSVC)                   \
    or defined(TETL_GCC)
    #define TETL_BUILTIN_HUGE_VALF (__builtin_huge_valf())
#else
    #define TETL_BUILTIN_HUGE_VALF (1.0F / 0.0F)
#endif

#if __has_builtin(__builtin_huge_val) or defined(TETL_MSVC) or defined(TETL_GCC)
    #define TETL_BUILTIN_HUGE_VAL (__builtin_huge_val())
#else
    #define TETL_BUILTIN_HUGE_VAL (1.0 / 0.0)
#endif

#if __has_builtin(__builtin_huge_vall) or defined(TETL_GCC)
    #define TETL_BUILTIN_HUGE_VALL (__builtin_huge_vall())
#elif defined(TETL_MSVC)
    #define TETL_BUILTIN_HUGE_VALL (__builtin_huge_val())
#else
    #define TETL_BUILTIN_HUGE_VALL (1.0L / 0.0L)
#endif

// VA LIST
#define TETL_BUILTIN_VA_LIST __builtin_va_list

// ASSUME ALIGNED
#if __has_builtin(__builtin_assume_aligned)
    #define TETL_BUILTIN_ASSUME_ALIGNED(p, a) __builtin_assume_aligned(p, a)
#else
    #define TETL_BUILTIN_ASSUME_ALIGNED(p, a) (p)
#endif

#if __has_builtin(__builtin_signbit) && !defined(TETL_CLANG)
    #define TETL_BUILTIN_SIGNBIT(x) __builtin_signbit(x)
#else
    #define TETL_BUILTIN_SIGNBIT(x) etl::detail::builtin_signbit_fallback(x)
#endif

// clang-format off

#if __has_builtin(__builtin_copysign)
#define TETL_BUILTIN_COPYSIGN(x, y) __builtin_copysign(x, y)
#else
#define TETL_BUILTIN_COPYSIGN(x, y) etl::detail::builtin_copysign_fallback(x, y)
#endif

#if __has_builtin(__builtin_copysignf)
#define TETL_BUILTIN_COPYSIGNF(x, y) __builtin_copysignf(x, y)
#else
#define TETL_BUILTIN_COPYSIGNF(x, y) etl::detail::builtin_copysign_fallback(x, y)
#endif

#if __has_builtin(__builtin_copysignl)
#define TETL_BUILTIN_COPYSIGNL(x, y) __builtin_copysignl(x, y)
#else
#define TETL_BUILTIN_COPYSIGNL(x, y) etl::detail::builtin_copysign_fallback(x, y)
#endif


#if __has_builtin(__builtin_is_constant_evaluated)
#define TETL_BUILTIN_IS_CONSTANT_EVALUATED() __builtin_is_constant_evaluated()
#else
#define TETL_BUILTIN_IS_CONSTANT_EVALUATED() false
#endif

#if defined(TETL_CLANG) or defined(TETL_MSVC)
#define TETL_BUILTIN_INT_SEQ(T, N) __make_integer_seq<integer_sequence, T, N>
#else
#define TETL_BUILTIN_INT_SEQ(T, N) integer_sequence<T, __integer_pack(N)...>
#endif

#define TETL_BUILTIN_HAS_UNIQUE_OBJECT_REPRESENTATION(Type) __has_unique_object_representations(Type)
#define TETL_BUILTIN_HAS_VIRTUAL_DESTRUCTOR(Type) __has_virtual_destructor(Type)
#define TETL_BUILTIN_IS_ABSTRACT(Type) __is_abstract(Type)
#define TETL_BUILTIN_IS_AGGREGATE(Type) __is_aggregate(Type)
#define TETL_BUILTIN_IS_ASSIGNABLE(Type, Arg) __is_assignable(Type, Arg)
#define TETL_BUILTIN_IS_CONSTRUCTIBLE(Type, Args) __is_constructible(Type, Args)
#define TETL_BUILTIN_IS_CLASS(Type) __is_class(Type)
#define TETL_BUILTIN_IS_ENUM(Type) __is_enum(Type)
#define TETL_BUILTIN_IS_FINAL(Type) __is_final(Type)
#define TETL_BUILTIN_IS_UNION(Type) __is_union(Type)
#define TETL_BUILTIN_IS_POLYMORPHIC(Type) __is_polymorphic(Type)
#define TETL_BUILTIN_IS_STANDARD_LAYOUT(Type) __is_standard_layout(Type)
#define TETL_BUILTIN_IS_TRIVIALLY_ASSIGNABLE(T, Arg) __is_trivially_assignable(T, Arg)
#define TETL_BUILTIN_IS_TRIVIAL_CONSTRUCTIBLE(Type) __is_trivially_constructible(Type)
#define TETL_BUILTIN_IS_TRIVIAL_DESTRUCTIBLE(Type) __has_trivial_destructor(Type)
#define TETL_BUILTIN_UNDERLYING_TYPE(Type) __underlying_type(Type)

// clang-format on

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