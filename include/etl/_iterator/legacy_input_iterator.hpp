// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_LEGACY_INPUT_ITERATOR_HPP
#define TETL_ITERATOR_LEGACY_INPUT_ITERATOR_HPP

#include <etl/_concepts/equality_comparable.hpp>
#include <etl/_concepts/signed_integral.hpp>
#include <etl/_iterator/incrementable_traits.hpp>
#include <etl/_iterator/indirectly_readable_traits.hpp>
#include <etl/_iterator/iter_reference_t.hpp>
#include <etl/_iterator/legacy_iterator.hpp>
#include <etl/_type_traits/common_reference.hpp>

namespace etl {

// clang-format off

/// \note Non-standard extension
/// \headerfile etl/iterator.hpp
/// \ingroup iterator
template <typename Iter>
concept legacy_input_iterator = etl::legacy_iterator<Iter> and etl::equality_comparable<Iter> and requires(Iter i) {
    typename etl::incrementable_traits<Iter>::difference_type;
    typename etl::indirectly_readable_traits<Iter>::value_type;
    // typename etl::common_reference_t<etl::iter_reference_t<Iter>&&, typename etl::indirectly_readable_traits<Iter>::value_type&>;
    *i++;
    // typename etl::common_reference_t<decltype(*i++)&&, typename etl::indirectly_readable_traits<Iter>::value_type&>;
    requires etl::signed_integral<typename etl::incrementable_traits<Iter>::difference_type>;
};

// clang-format on

} // namespace etl

#endif // TETL_ITERATOR_LEGACY_INPUT_ITERATOR_HPP
