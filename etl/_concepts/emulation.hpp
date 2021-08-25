/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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
template <typename T>
inline constexpr bool is_movable_v
    = etl::is_object_v<T>&& etl::is_assignable_v<T&, T>&&
        etl::is_move_constructible_v<T>&& etl::is_swappable_v<T&>;

template <typename Rng>
using range_iterator_t = decltype(etl::begin(etl::declval<Rng>()));

template <typename T>
using iterator_reference_t = typename etl::iterator_traits<T>::reference;

template <typename T>
using iterator_category_t = typename etl::iterator_traits<T>::iterator_category;

template <typename T, typename Category, typename = void>
struct Iterator_ : etl::false_type {
};

template <typename T, typename Category>
struct Iterator_<T, Category, etl::void_t<iterator_category_t<T>>>
    : etl::bool_constant<
          etl::is_convertible_v<iterator_category_t<T>, Category>> {
};

// Concepts (poor-man emulation using type traits)
// clang-format off
template <typename T> inline constexpr bool InputIterator           = Iterator_<T, etl::input_iterator_tag> {};
template <typename T> inline constexpr bool ForwardIterator         = Iterator_<T, etl::forward_iterator_tag> {};
template <typename T> inline constexpr bool OutputIterator          = Iterator_<T, etl::output_iterator_tag> {} || ForwardIterator<T>;
template <typename T> inline constexpr bool BidirectionalIterator   = Iterator_<T, etl::bidirectional_iterator_tag> {};
template <typename T> inline constexpr bool RandomAccessIterator    = Iterator_<T, etl::random_access_iterator_tag> {};
template <typename T> inline constexpr bool RandomAccessRange       = RandomAccessIterator<range_iterator_t<T>>;
// clang-format on

} // namespace etl::detail

#endif // TETL_CONCEPTS_EMULATION_HPP