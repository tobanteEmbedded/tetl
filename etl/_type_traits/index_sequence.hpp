/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_INDEX_SEQUENCE_HPP
#define TETL_TYPE_TRAITS_INDEX_SEQUENCE_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_type_traits/integer_sequence.hpp"

namespace etl {

/// \group integer_sequence
template <etl::size_t... Ints>
using index_sequence = etl::integer_sequence<etl::size_t, Ints...>;

/// \group integer_sequence
template <etl::size_t Size>
using make_index_sequence = etl::make_integer_sequence<etl::size_t, Size>;

/// \group integer_sequence
template <typename... T>
using index_sequence_for = etl::make_index_sequence<sizeof...(T)>;

} // namespace etl

#endif // TETL_TYPE_TRAITS_INDEX_SEQUENCE_HPP