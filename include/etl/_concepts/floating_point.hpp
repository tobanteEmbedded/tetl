// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_FLOATING_POINT_HPP
#define TETL_CONCEPTS_FLOATING_POINT_HPP

#include "etl/_type_traits/is_floating_point.hpp"

namespace etl {

/// \brief The concept floating_point<T> is satisfied if and only if T is a
/// floating-point type.
template <typename T>
concept floating_point = is_floating_point_v<T>;

} // namespace etl

#endif // TETL_CONCEPTS_FLOATING_POINT_HPP
