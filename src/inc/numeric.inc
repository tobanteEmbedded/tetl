// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

export namespace etl {

using etl::abs;
using etl::accumulate;
using etl::add_sat;
using etl::adjacent_difference;
using etl::div_sat;
using etl::gcd;
using etl::inner_product;
using etl::iota;
using etl::lcm;
using etl::midpoint;
using etl::partial_sum;
using etl::reduce;
using etl::saturate_cast;
using etl::transform_reduce;

namespace detail {
using etl::detail::add_sat_fallback;
} // namespace detail

} // namespace etl
