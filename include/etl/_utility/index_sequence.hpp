// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_UTILITY_INDEX_SEQUENCE_HPP
#define TETL_UTILITY_INDEX_SEQUENCE_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_utility/integer_sequence.hpp>

namespace etl {

template <etl::size_t... Ints>
using index_sequence = etl::integer_sequence<etl::size_t, Ints...>;

template <etl::size_t Size>
using make_index_sequence = etl::make_integer_sequence<etl::size_t, Size>;

template <typename... T>
using index_sequence_for = etl::make_index_sequence<sizeof...(T)>;

} // namespace etl

#endif // TETL_UTILITY_INDEX_SEQUENCE_HPP
