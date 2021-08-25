/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CONCEPTS_SIGNED_INTEGRAL_HPP
#define TETL_CONCEPTS_SIGNED_INTEGRAL_HPP

#include "etl/_concepts/integral.hpp"
#include "etl/_type_traits/is_signed.hpp"

#if defined(__cpp_concepts)
namespace etl {

/// \brief The concept signed_integral<T> is satisfied if and only if T is an
/// integral type and is_signed_v<T> is true.
template <typename T>
concept signed_integral = integral<T> && is_signed_v<T>;

} // namespace etl
#endif

#endif // TETL_CONCEPTS_SIGNED_INTEGRAL_HPP