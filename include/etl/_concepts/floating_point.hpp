/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CONCEPTS_FLOATING_POINT_HPP
#define TETL_CONCEPTS_FLOATING_POINT_HPP

#include "etl/_type_traits/is_floating_point.hpp"

#if defined(__cpp_concepts)
namespace etl {

/// \brief The concept floating_point<T> is satisfied if and only if T is a
/// floating-point type.
template <typename T>
concept floating_point = is_floating_point_v<T>;

} // namespace etl
#endif

#endif // TETL_CONCEPTS_FLOATING_POINT_HPP
