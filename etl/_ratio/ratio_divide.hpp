/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_RATIO_DIVIDE_HPP
#define TETL_RATIO_DIVIDE_HPP

#include "etl/_ratio/ratio.hpp"

namespace etl {

/// \brief The alias template ratio_divide denotes the result of dividing
/// two exact rational fractions represented by the ratio specializations
/// R1 and R2.
template <typename R1, typename R2>
using ratio_divide = ratio<R1::num * R2::den, R1::den * R2::num>;

} // namespace etl

#endif // TETL_RATIO_DIVIDE_HPP
