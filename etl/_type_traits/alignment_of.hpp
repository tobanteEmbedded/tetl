/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_ALIGNMENT_OF_HPP
#define TETL_TYPE_TRAITS_ALIGNMENT_OF_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_type_traits/integral_constant.hpp"

namespace etl {

/// \brief alignment_of
template <typename T>
struct alignment_of : integral_constant<etl::size_t, alignof(T)> {
};

template <typename T>
inline constexpr etl::size_t alignment_of_v = etl::alignment_of<T>::value;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ALIGNMENT_OF_HPP