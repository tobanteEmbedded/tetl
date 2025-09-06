// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_IS_FINAL_HPP
#define TETL_TYPE_TRAITS_IS_FINAL_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/bool_constant.hpp>

namespace etl {

/// \brief If T is a final class (that is, a class declared with the final
/// specifier), provides the member constant value equal true. For any other
/// type, value is false. If T is a class type, T shall be a complete type;
/// otherwise, the behavior is undefined.
template <typename T>
struct is_final : bool_constant<__is_final(T)> { };

template <typename T>
inline constexpr bool is_final_v = __is_final(T);

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_FINAL_HPP
