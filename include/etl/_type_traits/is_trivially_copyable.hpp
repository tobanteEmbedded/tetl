/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_IS_TRIVIALLY_COPYABLE_HPP
#define TETL_TYPE_TRAITS_IS_TRIVIALLY_COPYABLE_HPP

#include "etl/_config/all.hpp"

#include "etl/_type_traits/bool_constant.hpp"

namespace etl {

/// \brief If T is a TriviallyCopyable type, provides the member constant value
/// equal to true. For any other type, value is false. The only trivially
/// copyable types are scalar types, trivially copyable classes, and arrays of
/// such types/classes (possibly cv-qualified).
/// group is_trivial_copyable
template <typename T>
struct is_trivially_copyable : etl::bool_constant<__is_trivially_copyable(T)> { };

template <typename T>
inline constexpr bool is_trivially_copyable_v = __is_trivially_copyable(T);

} // namespace etl

#endif // TETL_TYPE_TRAITS_IS_TRIVIALLY_COPYABLE_HPP
