// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_SIGNED_INTEGRAL_HPP
#define TETL_CONCEPTS_SIGNED_INTEGRAL_HPP

#include <etl/_concepts/integral.hpp>
#include <etl/_type_traits/is_signed.hpp>

namespace etl {

/// \brief The concept signed_integral<T> is satisfied if and only if T is an
/// integral type and is_signed_v<T> is true.
template <typename T>
concept signed_integral = etl::integral<T> and etl::is_signed_v<T>;

} // namespace etl

#endif // TETL_CONCEPTS_SIGNED_INTEGRAL_HPP
