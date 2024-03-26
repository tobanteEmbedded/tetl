// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_LEGACY_BIDIRECTIONAL_ITERATOR_HPP
#define TETL_CONCEPTS_LEGACY_BIDIRECTIONAL_ITERATOR_HPP

#include <etl/_concepts/convertible_to.hpp>
#include <etl/_concepts/legacy_forward_iterator.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_iterator/iter_reference_t.hpp>

namespace etl {

template <typename Iter>
concept legacy_bidirectional_iterator = etl::legacy_forward_iterator<Iter> and requires(Iter i) {
    { --i } -> etl::same_as<Iter&>;
    { i-- } -> etl::convertible_to<Iter const&>;
    { *i-- } -> etl::same_as<etl::iter_reference_t<Iter>>;
};

} // namespace etl

#endif // TETL_CONCEPTS_LEGACY_BIDIRECTIONAL_ITERATOR_HPP
