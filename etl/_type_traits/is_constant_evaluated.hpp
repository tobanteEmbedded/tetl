/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_CONSTANT_EVALUATED_HPP
#define TETL_TYPE_TRAITS_IS_CONSTANT_EVALUATED_HPP

#include "etl/_config/all.hpp"

namespace etl {

/// \brief Detects whether the function call occurs within a constant-evaluated
/// context. Returns true if the evaluation of the call occurs within the
/// evaluation of an expression or conversion that is manifestly
/// constant-evaluated; otherwise returns false.
///
/// https://en.cppreference.com/w/cpp/types/is_constant_evaluated
[[nodiscard]] inline constexpr auto is_constant_evaluated() noexcept -> bool
{
#if __has_builtin(__builtin_is_constant_evaluated)
    return __builtin_is_constant_evaluated();
#else
    return false;
#endif
}

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_CONSTANT_EVALUATED_HPP
