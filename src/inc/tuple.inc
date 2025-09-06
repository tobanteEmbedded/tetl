// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

export namespace etl {

using etl::apply;
using etl::forward_as_tuple;
using etl::get;
using etl::ignore;
using etl::make_from_tuple;
using etl::make_tuple;
using etl::tie;
using etl::tuple;
using etl::tuple_cat;
using etl::tuple_element;
using etl::tuple_element_t;
using etl::tuple_size;
using etl::operator==;
using etl::swap;
using etl::tuple_size_v;

// Non-standard extensions
using etl::pair_like;
using etl::tuple_like;

} // namespace etl
