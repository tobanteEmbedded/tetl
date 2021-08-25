/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_RATIO_MULTIPLY_HPP
#define TETL_RATIO_MULTIPLY_HPP

#include "etl/_ratio/ratio.hpp"

namespace etl {

/// \brief The alias template ratio_multiply denotes the result of
/// multiplying two exact rational fractions represented by the ratio
/// specializations R1 and R2.
///
/// \details The result is a ratio specialization `ratio<U, V>`, such
/// that given Num == R1::num * R2::num and Denom == R1::den * R2::den (computed
/// without arithmetic overflow), U is ratio<Num, Denom>::num and V is
/// ratio<Num, Denom>::den.
///
/// \todo Check overflow.
template <typename R1, typename R2>
using ratio_multiply = ratio<R1::num * R2::num, R1::den * R2::den>;

} // namespace etl

#endif // TETL_RATIO_MULTIPLY_HPP