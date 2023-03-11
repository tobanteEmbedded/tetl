/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MEMORY_USES_ALLOCATOR_HPP
#define TETL_MEMORY_USES_ALLOCATOR_HPP

#include "etl/_type_traits/bool_constant.hpp"
#include "etl/_type_traits/is_convertible.hpp"
#include "etl/_type_traits/void_t.hpp"

namespace etl {

namespace detail {
template <typename Type, typename Alloc, typename = void>
struct uses_allocator_impl : false_type { };

template <typename Type, typename Alloc>
struct uses_allocator_impl<Type, Alloc, void_t<typename Type::allocator_type>>
    : is_convertible<Alloc, typename Type::allocator_type>::type { };
} // namespace detail

/// \brief If T has a member typedef allocator_type which is convertible from
/// Alloc, the member constant value is true. Otherwise value is false.
template <typename Type, typename Alloc>
struct uses_allocator : detail::uses_allocator_impl<Type, Alloc>::type { };

/// \brief If T has a member typedef allocator_type which is convertible from
/// Alloc, the member constant value is true. Otherwise value is false.
template <typename Type, typename Alloc>
inline constexpr auto uses_allocator_v = uses_allocator<Type, Alloc>::value;

} // namespace etl

#endif // TETL_MEMORY_USES_ALLOCATOR_HPP
