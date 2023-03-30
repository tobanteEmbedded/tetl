// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONCEPTS_EMULATION_HPP
#define TETL_CONCEPTS_EMULATION_HPP

#include "etl/_iterator/begin.hpp"
#include "etl/_iterator/end.hpp"
#include "etl/_iterator/iterator_traits.hpp"
#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/is_assignable.hpp"
#include "etl/_type_traits/is_convertible.hpp"
#include "etl/_type_traits/is_move_constructible.hpp"
#include "etl/_type_traits/is_object.hpp"
#include "etl/_type_traits/is_swappable.hpp"
#include "etl/_type_traits/void_t.hpp"

namespace etl::detail {

// Concepts (poor-man emulation using type traits)
/// Copied from https://github.com/gnzlbg/static_vector

// clang-format off

template <typename T>
inline constexpr bool is_movable_v
        = etl::is_object_v<T>
        && etl::is_assignable_v<T&, T>
        && etl::is_move_constructible_v<T>
        && etl::is_swappable_v<T&>;

template <typename Rng>
using range_iterator_t = decltype(etl::begin(etl::declval<Rng>()));

template <typename T>
using iterator_reference_t = typename etl::iterator_traits<T>::reference;

template <typename T>
using iterator_category_t = typename etl::iterator_traits<T>::iterator_category;

template <typename T, typename Category, typename = void>
struct IteratorConcept : etl::false_type { };

template <typename T, typename Category>
struct IteratorConcept<T, Category, etl::void_t<iterator_category_t<T>>>
    : etl::bool_constant<etl::is_convertible_v<iterator_category_t<T>, Category>> {
};

template <typename T> inline constexpr bool InputIterator           = IteratorConcept<T, etl::input_iterator_tag> {};
template <typename T> inline constexpr bool ForwardIterator         = IteratorConcept<T, etl::forward_iterator_tag> {};
template <typename T> inline constexpr bool OutputIterator          = IteratorConcept<T, etl::output_iterator_tag> {} || ForwardIterator<T>;
template <typename T> inline constexpr bool BidirectionalIterator   = IteratorConcept<T, etl::bidirectional_iterator_tag> {};
template <typename T> inline constexpr bool RandomAccessIterator    = IteratorConcept<T, etl::random_access_iterator_tag> {};
template <typename T> inline constexpr bool RandomAccessRange       = RandomAccessIterator<range_iterator_t<T>>;
// clang-format on

} // namespace etl::detail

#endif // TETL_CONCEPTS_EMULATION_HPP
