// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

export namespace etl {

using etl::bad_function_call;
using etl::bind_front;
using etl::bit_and;
using etl::bit_not;
using etl::bit_or;
using etl::bit_xor;
using etl::cref;
using etl::default_searcher;
using etl::divides;
using etl::equal_to;
using etl::greater;
using etl::greater_equal;
using etl::hash;
using etl::identity;
using etl::invoke;
using etl::invoke_r;
using etl::is_placeholder;
using etl::less;
using etl::less_equal;
using etl::logical_and;
using etl::logical_not;
using etl::logical_or;
using etl::minus;
using etl::modulus;
using etl::multiplies;
using etl::negate;
using etl::not_equal_to;
using etl::not_fn;
using etl::plus;
using etl::ref;
using etl::reference_wrapper;
using etl::operator==;
using etl::operator!=;

// clang-format off
using etl::placeholders::_1;
using etl::placeholders::_2;
using etl::placeholders::_3;
using etl::placeholders::_4;
using etl::placeholders::_5;
using etl::placeholders::_6;
using etl::placeholders::_7;
using etl::placeholders::_8;
using etl::placeholders::_9;
using etl::placeholders::_10;
using etl::placeholders::_11;
using etl::placeholders::_12;
using etl::placeholders::_13;
using etl::placeholders::_14;
using etl::placeholders::_15;
using etl::placeholders::_16;
using etl::placeholders::_17;
using etl::placeholders::_18;
using etl::placeholders::_19;
using etl::placeholders::_20;
using etl::placeholders::_21;
using etl::placeholders::_22;
using etl::placeholders::_23;
using etl::placeholders::_24;
using etl::placeholders::_25;
using etl::placeholders::_26;
using etl::placeholders::_27;
using etl::placeholders::_28;
using etl::placeholders::_29;
using etl::placeholders::_30;
using etl::placeholders::_31;
using etl::placeholders::_32;
// clang-format on

// Non-standard extensions
using etl::fnv1a;
using etl::fnv1a32;
using etl::fnv1a64;
using etl::function_ref;
using etl::inplace_function;

namespace detail {
using etl::detail::is_transparent;
using etl::detail::is_transparent_v;
} // namespace detail

} // namespace etl
