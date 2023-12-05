// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_SENTINEL_FOR_HPP
#define TETL_ITERATOR_SENTINEL_FOR_HPP

#include <etl/_concepts/semiregular.hpp>
#include <etl/_concepts/weakly_equality_comparable_with.hpp>
#include <etl/_iterator/input_or_output_iterator.hpp>

namespace etl {

template <typename S, typename Iter>
concept sentinel_for = semiregular<S> and input_or_output_iterator<Iter> and weakly_equality_comparable_with<S, Iter>;

} // namespace etl

#endif // TETL_ITERATOR_SENTINEL_FOR_HPP
