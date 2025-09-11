// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_ALIGNMENT_OF_HPP
#define TETL_TYPE_TRAITS_ALIGNMENT_OF_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/integral_constant.hpp>

namespace etl {

/// \brief alignment_of
/// \ingroup type_traits
template <typename T>
struct alignment_of : integral_constant<size_t, alignof(T)> { };

/// \ingroup type_traits
template <typename T>
inline constexpr size_t alignment_of_v = alignment_of<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ALIGNMENT_OF_HPP
