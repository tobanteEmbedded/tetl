// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

export namespace etl {

using etl::abs;
using etl::arg;
using etl::complex;
using etl::conj;
using etl::cos;
using etl::cosh;
using etl::get;
using etl::imag;
using etl::log;
using etl::log10;
using etl::norm;
using etl::polar;
using etl::real;
using etl::sin;
using etl::sinh;
using etl::tan;
using etl::tanh;
using etl::tuple_element;
using etl::tuple_element_t;
using etl::tuple_size;
using etl::tuple_size_v;

using etl::operator+;
using etl::operator-;
using etl::operator*;
using etl::operator/;

inline namespace literals {
inline namespace complex_literals {
using etl::literals::complex_literals::operator""_il;
using etl::literals::complex_literals::operator""_i;
using etl::literals::complex_literals::operator""_if;
} // namespace complex_literals
} // namespace literals

} // namespace etl
