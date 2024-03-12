// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_RELATION_HPP
#define TETL_CONCEPTS_RELATION_HPP

#include <etl/_concepts/predicate.hpp>

namespace etl {

template <typename R, typename T, typename U>
concept relation = predicate<R, T, T> and predicate<R, U, U> and predicate<R, T, U> and predicate<R, U, T>;

} // namespace etl

#endif // TETL_CONCEPTS_RELATION_HPP
