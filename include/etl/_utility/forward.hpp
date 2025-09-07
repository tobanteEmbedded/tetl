// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_UTILITY_FORWARD_HPP
#define TETL_UTILITY_FORWARD_HPP

#include <etl/_type_traits/remove_reference.hpp>

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

#endif // TETL_UTILITY_FORWARD_HPP
