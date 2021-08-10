// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

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