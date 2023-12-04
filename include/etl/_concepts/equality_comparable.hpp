// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_EQUALITY_COMPARABLE_HPP
#define TETL_CONCEPTS_EQUALITY_COMPARABLE_HPP

#include "etl/_concepts/weakly_equality_comparable_with.hpp"

namespace etl {

template <typename T>
concept equality_comparable = weakly_equality_comparable_with<T, T>;

} // namespace etl

#endif // TETL_CONCEPTS_EQUALITY_COMPARABLE_HPP
