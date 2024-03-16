// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RATIO_ADD_HPP
#define TETL_RATIO_ADD_HPP

#include <etl/_ratio/ratio.hpp>

namespace etl {

/// \brief The alias template ratio_add denotes the result of adding two
/// exact rational fractions represented by the ratio specializations R1
/// and R2.
template <typename R1, typename R2>
using ratio_add = ratio<R1::num * R2::den + R2::num * R1::den, R1::den * R2::den>;

} // namespace etl

#endif // TETL_RATIO_ADD_HPP
