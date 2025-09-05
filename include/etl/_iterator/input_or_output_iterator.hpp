// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_INPUT_OR_OUTPUT_ITERATOR_HPP
#define TETL_ITERATOR_INPUT_OR_OUTPUT_ITERATOR_HPP

#include <etl/_concepts/weakly_equality_comparable_with.hpp>
#include <etl/_iterator/can_reference.hpp>
#include <etl/_iterator/weakly_incrementable.hpp>

namespace etl {

template <typename Iter>
concept input_or_output_iterator = weakly_incrementable<Iter> and requires(Iter it) {
    { *it } -> detail::can_reference;
};

} // namespace etl

#endif // TETL_ITERATOR_INPUT_OR_OUTPUT_ITERATOR_HPP
