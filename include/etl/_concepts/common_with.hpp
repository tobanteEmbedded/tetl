/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CONCEPTS_COMMON_WITH_HPP
#define TETL_CONCEPTS_COMMON_WITH_HPP

#include "etl/_concepts/same_as.hpp"
#include "etl/_type_traits/add_lvalue_reference.hpp"
#include "etl/_type_traits/common_reference.hpp"
#include "etl/_type_traits/common_type.hpp"
#include "etl/_type_traits/declval.hpp"

#if defined(__cpp_concepts)
namespace etl {

// clang-format off
template <class T, class U>
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
#endif

#endif // TETL_CONCEPTS_COMMON_WITH_HPP
