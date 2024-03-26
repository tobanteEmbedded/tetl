// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_LEGACY_FORWARD_ITERATOR_HPP
#define TETL_CONCEPTS_LEGACY_FORWARD_ITERATOR_HPP

#include <etl/_concepts/constructible_from.hpp>
#include <etl/_concepts/convertible_to.hpp>
#include <etl/_concepts/legacy_input_iterator.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_iterator/indirectly_readable_traits.hpp>
#include <etl/_iterator/iter_reference_t.hpp>
#include <etl/_type_traits/is_reference.hpp>
#include <etl/_type_traits/remove_cvref.hpp>

namespace etl {

// clang-format off
template <typename Iter>
concept legacy_forward_iterator = legacy_input_iterator<Iter>
    and etl::constructible_from<Iter>
    and etl::is_reference_v<etl::iter_reference_t<Iter>>
    and etl::same_as<etl::remove_cvref_t<etl::iter_reference_t<Iter>>, typename etl::indirectly_readable_traits<Iter>::value_type>
    and requires(Iter it) {
          { it++ } -> etl::convertible_to<Iter const&>;
          { *it++ } -> etl::same_as<etl::iter_reference_t<Iter>>;
    };
// clang-format on

} // namespace etl

#endif // TETL_CONCEPTS_LEGACY_FORWARD_ITERATOR_HPP
