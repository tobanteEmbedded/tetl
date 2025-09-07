// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_CHRONO_IS_CLOCK_HPP
#define TETL_CHRONO_IS_CLOCK_HPP

#include <etl/_type_traits/bool_constant.hpp>

namespace etl::chrono {

/// \brief If T satisfies the Clock requirements, provides the member
///        constant value equal true. For any other type, value is false.
/// \details https://en.cppreference.com/w/cpp/chrono/is_clock
/// \ingroup chrono
template <typename>
struct is_clock : etl::false_type { };

/// \ingroup chrono
template <typename T>
inline constexpr bool is_clock_v = is_clock<T>::value;

} // namespace etl::chrono

#endif // TETL_CHRONO_IS_CLOCK_HPP
