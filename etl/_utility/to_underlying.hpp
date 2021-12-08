/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_UTILITY_TO_UNDERLYING_HPP
#define TETL_UTILITY_TO_UNDERLYING_HPP

#include "etl/_type_traits/underlying_type.hpp"

namespace etl {

/// \brief Converts an enumeration to its underlying type.
///
/// https://en.cppreference.com/w/cpp/utility/to_underlying
template <typename Enum>
[[nodiscard]] constexpr auto to_underlying(Enum e) noexcept -> underlying_type_t<Enum>
{
    return static_cast<underlying_type_t<Enum>>(e);
}

} // namespace etl

#endif // TETL_UTILITY_TO_UNDERLYING_HPP