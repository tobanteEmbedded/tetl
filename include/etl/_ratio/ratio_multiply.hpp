// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RATIO_MULTIPLY_HPP
#define TETL_RATIO_MULTIPLY_HPP

#include <etl/_ratio/ratio.hpp>

namespace etl {

/// \brief The alias template ratio_multiply denotes the result of
/// multiplying two exact rational fractions represented by the ratio
/// specializations R1 and R2.
/// \ingroup ratio
template <typename R1, typename R2>
using ratio_multiply = ratio<R1::num * R2::num, R1::den * R2::den>;

} // namespace etl

#endif // TETL_RATIO_MULTIPLY_HPP
