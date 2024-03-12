// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_UNSIGNED_INTEGRAL_HPP
#define TETL_CONCEPTS_UNSIGNED_INTEGRAL_HPP

#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_unsigned.hpp>

namespace etl {

/// \brief The concept unsigned_integral<T> is satisfied if and only if T is an
/// integral type and is_unsigned_v<T> is true.
template <typename T>
concept unsigned_integral = etl::integral<T> && etl::is_unsigned_v<T>;

} // namespace etl

#endif // TETL_CONCEPTS_UNSIGNED_INTEGRAL_HPP
