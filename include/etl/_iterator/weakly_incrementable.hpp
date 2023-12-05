// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_WEAKLY_INCREMENTABLE_HPP
#define TETL_ITERATOR_WEAKLY_INCREMENTABLE_HPP

#include <etl/_concepts/movable.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_concepts/signed_integral.hpp>
#include <etl/_iterator/iter_difference_t.hpp>

namespace etl {

// clang-format off
template <typename It>
concept weakly_incrementable = etl::movable<It> && requires(It i) {
    typename etl::iter_difference_t<It>;
    requires etl::signed_integral<etl::iter_difference_t<It>>;
    { ++i } -> etl::same_as<It&>;
    i++;
};
// clang-format on

} // namespace etl

#endif // TETL_ITERATOR_WEAKLY_INCREMENTABLE_HPP
