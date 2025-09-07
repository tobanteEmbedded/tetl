// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

export namespace etl {

using etl::advance;
using etl::back_insert_iterator;
using etl::back_inserter;
using etl::begin;
using etl::bidirectional_iterator_tag;
using etl::cbegin;
using etl::cend;
using etl::contiguous_iterator_tag;
using etl::crbegin;
using etl::crend;
using etl::data;
using etl::distance;
using etl::empty;
using etl::end;
using etl::forward_iterator_tag;
using etl::front_insert_iterator;
using etl::front_inserter;
using etl::incrementable;
using etl::incrementable_traits;
using etl::indirect_result_t;
using etl::indirectly_readable;
using etl::indirectly_readable_traits;
using etl::indirectly_regular_unary_invocable;
using etl::indirectly_unary_invocable;
using etl::input_iterator_tag;
using etl::input_or_output_iterator;
using etl::iter_common_reference_t;
using etl::iter_difference_t;
using etl::iter_reference_t;
using etl::iter_rvalue_reference_t;
using etl::iter_value_t;
using etl::iterator_traits;
using etl::make_reverse_iterator;
using etl::next;
using etl::output_iterator_tag;
using etl::prev;
using etl::projected;
using etl::random_access_iterator_tag;
using etl::rbegin;
using etl::rend;
using etl::reverse_iterator;
using etl::sentinel_for;
using etl::size;
using etl::weakly_incrementable;

namespace ranges {
using etl::ranges::iter_move;
} // namespace ranges

// Non-standard extensions
using etl::full;
using etl::legacy_bidirectional_iterator;
using etl::legacy_forward_iterator;
using etl::legacy_input_iterator;
using etl::legacy_iterator;

} // namespace etl
