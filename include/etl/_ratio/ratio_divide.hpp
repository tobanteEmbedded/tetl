// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RATIO_DIVIDE_HPP
#define TETL_RATIO_DIVIDE_HPP

#include <etl/_ratio/ratio.hpp>

namespace etl {

/// \brief The alias template ratio_divide denotes the result of dividing
/// two exact rational fractions represented by the ratio specializations
/// R1 and R2.
/// \ingroup ratio
template <typename R1, typename R2>
using ratio_divide = ratio<R1::num * R2::den, R1::den * R2::num>;

} // namespace etl

#endif // TETL_RATIO_DIVIDE_HPP
