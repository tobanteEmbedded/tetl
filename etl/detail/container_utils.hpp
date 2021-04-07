/*
Copyright (c) Tobias Hienzsch. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_CONTAINER_UTILS_HPP
#define TAETL_CONTAINER_UTILS_HPP

#include "etl/cstddef.hpp"
#include "etl/iterator.hpp"
#include "etl/limits.hpp"
#include "etl/type_traits.hpp"
#include "etl/utility.hpp"

#include "etl/detail/sfinae.hpp"

namespace etl::detail
{
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

template <typename T, typename Cat, typename = void>
struct Iterator_ : etl::false_type
{
};

template <typename T, typename Cat>
struct Iterator_<T, Cat, etl::void_t<iterator_category_t<T>>>
    : etl::bool_constant<etl::is_convertible_v<iterator_category_t<T>, Cat>>
{
};

// Concepts (poor-man emulation using type traits)
template <typename T>
static constexpr bool InputIterator = Iterator_<T, etl::input_iterator_tag> {};

template <typename T>
static constexpr bool ForwardIterator
  = Iterator_<T, etl::forward_iterator_tag> {};

template <typename T>
static constexpr bool OutputIterator
  = Iterator_<T, etl::output_iterator_tag> {} || ForwardIterator<T>;

template <typename T>
static constexpr bool BidirectionalIterator
  = Iterator_<T, etl::bidirectional_iterator_tag> {};

template <typename T>
static constexpr bool RandomAccessIterator
  = Iterator_<T, etl::random_access_iterator_tag> {};

template <typename T>
static constexpr bool RandomAccessRange
  = RandomAccessIterator<range_iterator_t<T>>;

/**
 * @brief Smallest fixed-width unsigned integer type that can represent values
 * in the range [0, N].
 */
// clang-format off
template<size_t N>
using smallest_size_t =
            etl::conditional_t<(N < etl::numeric_limits<uint8_t>::max()),  uint8_t,
            etl::conditional_t<(N < etl::numeric_limits<uint16_t>::max()), uint16_t,
            etl::conditional_t<(N < etl::numeric_limits<uint32_t>::max()), uint32_t,
            etl::conditional_t<(N < etl::numeric_limits<uint64_t>::max()), uint64_t,
                                                                 size_t>>>>;
// clang-format on

/**
 * @brief Index a range doing bound checks in debug builds
 */
template <typename Rng, typename Index, TAETL_REQUIRES_(RandomAccessRange<Rng>)>
constexpr auto index(Rng&& rng, Index&& i) noexcept -> decltype(auto)
{
  assert(static_cast<ptrdiff_t>(i) < (etl::end(rng) - etl::begin(rng)));
  return etl::begin(etl::forward<Rng>(rng))[etl::forward<Index>(i)];
}
}  // namespace etl::detail
#endif  // TAETL_CONTAINER_UTILS_HPP