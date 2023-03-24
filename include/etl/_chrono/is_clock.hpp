/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_IS_CLOCK_HPP
#define TETL_CHRONO_IS_CLOCK_HPP

#include "etl/_type_traits/bool_constant.hpp"

namespace etl::chrono {

/// \brief If T satisfies the Clock requirements, provides the member
///        constant value equal true. For any other type, value is false.
/// \details https://en.cppreference.com/w/cpp/chrono/is_clock
template <typename>
struct is_clock : etl::false_type { };

template <typename T>
inline constexpr bool is_clock_v = is_clock<T>::value;

} // namespace etl::chrono

#endif // TETL_CHRONO_IS_CLOCK_HPP
