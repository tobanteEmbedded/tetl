// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CONCEPTS_INTEGRAL_HPP
#define TETL_CONCEPTS_INTEGRAL_HPP

#include <etl/_type_traits/is_integral.hpp>

namespace etl {

/// \brief The concept integral<T> is satisfied if and only if T is an integral type.
/// \ingroup concepts
template <typename T>
concept integral = is_integral_v<T>;

} // namespace etl

#endif // TETL_CONCEPTS_INTEGRAL_HPP
