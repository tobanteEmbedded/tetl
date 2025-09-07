// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch


export namespace etl {

using etl::bit_cast;
using etl::bit_ceil;
using etl::bit_floor;
using etl::bit_width;
using etl::byteswap;
using etl::countl_one;
using etl::countl_zero;
using etl::countr_one;
using etl::countr_zero;
using etl::endian;
using etl::has_single_bit;
using etl::popcount;
using etl::rotl;
using etl::rotr;

// Non-standard extensions
using etl::flip_bit;
using etl::reset_bit;
using etl::set_bit;
using etl::test_bit;

namespace detail {
using etl::detail::byteswap_fallback;
using etl::detail::popcount_fallback;
} // namespace detail

} // namespace etl
