// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_INPUT_OR_OUTPUT_ITERATOR_HPP
#define TETL_ITERATOR_INPUT_OR_OUTPUT_ITERATOR_HPP

#include <etl/_concepts/weakly_equality_comparable_with.hpp>
#include <etl/_iterator/can_reference.hpp>
#include <etl/_iterator/weakly_incrementable.hpp>

namespace etl {

// clang-format off
template <typename It>
concept input_or_output_iterator = weakly_incrementable<It> and requires(It it) {
    { *it } -> detail::can_reference;
};
// clang-format on

} // namespace etl

#endif // TETL_ITERATOR_INPUT_OR_OUTPUT_ITERATOR_HPP
