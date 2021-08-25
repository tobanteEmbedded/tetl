/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CHRONO_TREAT_AS_FLOATING_POINT_HPP
#define TETL_CHRONO_TREAT_AS_FLOATING_POINT_HPP

#include "etl/_type_traits/is_floating_point.hpp"

namespace etl::chrono {

/// \brief The etl::chrono::treat_as_floating_point trait helps determine if a
/// duration can be converted to another duration with a different tick period.
/// \details Implicit conversions between two durations normally depends on the
/// tick period of the durations. However, implicit conversions can happen
/// regardless of tick period if
/// etl::chrono::treat_as_floating_point<Rep>::value == true.
/// \note etl::chrono::treat_as_floating_point may be specialized for
/// program-defined types.
/// \group treat_as_floating_point
template <typename Rep>
struct treat_as_floating_point : etl::is_floating_point<Rep> {
};

/// \group treat_as_floating_point
template <typename Rep>
inline constexpr bool treat_as_floating_point_v
    = treat_as_floating_point<Rep>::value;

} // namespace etl::chrono

#endif // TETL_CHRONO_TREAT_AS_FLOATING_POINT_HPP