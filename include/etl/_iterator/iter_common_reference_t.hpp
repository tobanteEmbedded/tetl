// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_ITERATOR_ITER_COMMON_REFERENCE_T_HPP
#define TETL_ITERATOR_ITER_COMMON_REFERENCE_T_HPP

#include <etl/_iterator/dereferenceable.hpp>
#include <etl/_iterator/iter_reference_t.hpp>
#include <etl/_iterator/iter_value_t.hpp>
#include <etl/_type_traits/common_reference.hpp>

namespace etl {

/// \ingroup iterator
template <etl::indirectly_readable T>
using iter_common_reference_t = etl::common_reference_t<etl::iter_reference_t<T>, etl::iter_value_t<T>&>;

} // namespace etl

#endif // TETL_ITERATOR_ITER_COMMON_REFERENCE_T_HPP
