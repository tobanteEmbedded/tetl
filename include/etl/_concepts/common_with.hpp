// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CONCEPTS_COMMON_WITH_HPP
#define TETL_CONCEPTS_COMMON_WITH_HPP

#include <etl/_concepts/same_as.hpp>
#include <etl/_type_traits/add_lvalue_reference.hpp>
#include <etl/_type_traits/common_reference.hpp>
#include <etl/_type_traits/common_type.hpp>
#include <etl/_type_traits/declval.hpp>

namespace etl {

// clang-format off
/// \ingroup concepts
template <typename T, typename U>
concept common_with =
  same_as<common_type_t<T, U>, common_type_t<U, T>> &&
  requires {
    static_cast<common_type_t<T, U>>(declval<T>());
    static_cast<common_type_t<T, U>>(declval<U>());
  } &&
  common_reference_with<
    add_lvalue_reference_t<T const>,
    add_lvalue_reference_t<U const>> &&
  common_reference_with<
    add_lvalue_reference_t<common_type_t<T, U>>,
    common_reference_t<
      add_lvalue_reference_t<T const>,
      add_lvalue_reference_t<U const>>>;
// clang-format on

} // namespace etl

#endif // TETL_CONCEPTS_COMMON_WITH_HPP
