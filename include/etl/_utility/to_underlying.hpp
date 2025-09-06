// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_UTILITY_TO_UNDERLYING_HPP
#define TETL_UTILITY_TO_UNDERLYING_HPP

#include <etl/_type_traits/underlying_type.hpp>

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
