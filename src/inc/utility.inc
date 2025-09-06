// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

export namespace etl {

using etl::as_const;
using etl::basic_common_reference;
using etl::cmp_equal;
using etl::cmp_greater;
using etl::cmp_greater_equal;
using etl::cmp_less;
using etl::cmp_less_equal;
using etl::cmp_not_equal;
using etl::declval;
using etl::exchange;
using etl::forward;
using etl::forward_like;
using etl::in_range;
using etl::index_sequence;
using etl::index_sequence_for;
using etl::integer_sequence;
using etl::make_index_sequence;
using etl::make_integer_sequence;
using etl::move;
using etl::move_if_noexcept;
using etl::pair;
using etl::swap;
using etl::to_underlying;
using etl::unreachable;
using etl::operator==;
using etl::operator!=;
using etl::operator<;
using etl::operator>;
using etl::operator<=;
using etl::operator>=;
using etl::get;
using etl::in_place;
using etl::in_place_index;
using etl::in_place_index_t;
using etl::in_place_t;
using etl::in_place_type;
using etl::in_place_type_t;
using etl::make_pair;
using etl::piecewise_construct;
using etl::piecewise_construct_t;
using etl::tuple_element;
using etl::tuple_element_t;
using etl::tuple_size;
using etl::tuple_size_v;

// Non-standard extensions
using etl::ignore_unused;

} // namespace etl
