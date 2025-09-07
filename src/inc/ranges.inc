// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

export namespace etl {

using etl::decay_copy;

namespace ranges {
using etl::ranges::begin;
using etl::ranges::borrowed_iterator_t;
using etl::ranges::borrowed_range;
using etl::ranges::dangling;
using etl::ranges::disable_sized_range;
using etl::ranges::enable_borrowed_range;
using etl::ranges::end;
using etl::ranges::iterator_t;
using etl::ranges::range;
using etl::ranges::range_difference_t;
using etl::ranges::range_reference_t;
using etl::ranges::range_size_t;
using etl::ranges::range_value_t;
using etl::ranges::sentinel_t;
using etl::ranges::size;
using etl::ranges::sized_range;
} // namespace ranges

} // namespace etl
