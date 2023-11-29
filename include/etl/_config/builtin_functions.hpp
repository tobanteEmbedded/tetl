// SPDX-License-Identifier: BSL-1.0

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
    #define TETL_BUILTIN_UNREACHABLE                                                                                   \
        {                                                                                                              \
            struct etl_builtin_unreachable_t {                                                                         \
                etl_builtin_unreachable_t& operator=(etl_builtin_unreachable_t const&);                                \
            } x;                                                                                                       \
            x = x;                                                                                                     \
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

// HUGE VAL
#if __has_builtin(__builtin_huge_valf) or defined(TETL_MSVC) or defined(TETL_GCC)
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

// clang-format off
#if defined(TETL_CLANG) or defined(TETL_MSVC)
    #define TETL_BUILTIN_INT_SEQ(T, N) __make_integer_seq<integer_sequence, T, N>
#else
    #define TETL_BUILTIN_INT_SEQ(T, N) integer_sequence<T, __integer_pack(N)...>
#endif
// clang-format on

#endif // TETL_CONFIG_BUILTIN_FUNCTIONS_HPP
