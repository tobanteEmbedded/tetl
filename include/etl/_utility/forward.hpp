// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_FORWARD_HPP
#define TETL_UTILITY_FORWARD_HPP

#include "etl/_type_traits/remove_reference.hpp"

namespace etl {

/// \brief Forwards lvalues as either lvalues or as rvalues, depending on T.
/// When t is a forwarding reference (a function argument that is declared as an
/// rvalue reference to a cv-unqualified function template parameter), this
/// overload forwards the argument to another function with the value category
/// it had when passed to the calling function.
///
/// https://en.cppreference.com/w/cpp/utility/forward
template <typename T>
constexpr auto forward(remove_reference_t<T>& param) noexcept -> T&&
{
    return static_cast<T&&>(param);
}

template <typename T>
constexpr auto forward(remove_reference_t<T>&& param) noexcept -> T&&
{
    return static_cast<T&&>(param);
}

} // namespace etl

// https://www.foonathan.net/2020/09/move-forward
#define TETL_FORWARD(...) static_cast<decltype(__VA_ARGS__)&&>(__VA_ARGS__)

#endif // TETL_UTILITY_FORWARD_HPP
