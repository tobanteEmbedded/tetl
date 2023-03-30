// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTDARG_TYPEDEFS_HPP
#define TETL_CSTDARG_TYPEDEFS_HPP

#include "etl/_config/all.hpp"

#if defined(TETL_MSVC)
    #include <cstdarg>
#endif

namespace etl {
#if not defined(TETL_MSVC)

/// \brief va_list is a complete object type suitable for holding the
/// information needed by the macros va_start, va_copy, va_arg, and va_end. If a
/// va_list instance is created, passed to another function, and used via va_arg
/// in that function, then any subsequent use in the calling function should be
/// preceded by a call to va_end. It is legal to pass a pointer to a va_list
/// object to another function and then use that object after the function
/// returns.
///
/// https://en.cppreference.com/w/cpp/utility/variadic/va_list
using va_list = TETL_BUILTIN_VA_LIST;
#else
using va_list = ::std::va_list;
#endif
} // namespace etl

#if not defined(va_start)

    /// \brief The va_start macro enables access to the variable arguments
    /// following the named argument parm_n. va_start should be invoked with an
    /// instance to a valid va_list object ap before any calls to va_arg. If the
    /// parm_n is a pack expansion or an entity resulting from a lambda capture,
    /// the program is ill-formed, no diagnostic required. If parm_n is declared
    /// with reference type or with a type not compatible with the type that
    /// results from default argument promotions, the behavior is undefined.
    ///
    /// https://en.cppreference.com/w/cpp/utility/variadic/va_start
    #define va_start(ap, param) __builtin_va_start(ap, param)
#endif

#if not defined(va_end)

    /// \brief The va_end macro performs cleanup for an ap object initialized by
    /// a call to va_start or va_copy. va_end may modify ap so that it is no
    /// longer usable.
    ///
    /// \details If there is no corresponding call to va_start or va_copy, or if
    /// va_end is not called before a function that calls va_start or va_copy
    /// returns, the behavior is undefined.
    ///
    /// https://en.cppreference.com/w/cpp/utility/variadic/va_end
    #define va_end(ap) __builtin_va_end(ap)
#endif

#if not defined(va_arg)

    /// \brief The va_arg macro expands to an expression of type T that
    /// corresponds to the next parameter from the va_list ap. Prior to calling
    /// va_arg, ap must be initialized by a call to either va_start or va_copy,
    /// with no intervening call to va_end. Each invocation of the va_arg macro
    /// modifies ap to point to the next variable argument.
    ///
    /// https://en.cppreference.com/w/cpp/utility/variadic/va_arg
    #define va_arg(ap, type) __builtin_va_arg(ap, type)
#endif

#if not defined(va_copy)

    /// \brief The va_copy macro copies src to dest.
    ///
    /// \details va_end should be called on dest before the function returns or
    /// any subsequent re-initialization of dest (via calls to va_start or
    /// va_copy).
    ///
    /// https://en.cppreference.com/w/cpp/utility/variadic/va_copy
    #define va_copy(dest, src) __builtin_va_copy(dest, src)
#endif

#endif // TETL_CSTDARG_TYPEDEFS_HPP
