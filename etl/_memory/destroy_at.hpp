/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MEMORY_DESTROY_AT_HPP
#define TETL_MEMORY_DESTROY_AT_HPP

#include "etl/_memory/addressof.hpp"
#include "etl/_type_traits/is_array.hpp"

namespace etl {

/// \brief If T is not an array type, calls the destructor of the object pointed
/// to by p, as if by p->~T(). If T is an array type, recursively destroys
/// elements of *p in order, as if by calling destroy(begin(*p),
/// end(*p)).
template <typename T>
constexpr auto destroy_at(T* p) -> void
{
    if constexpr (etl::is_array_v<T>) {
        for (auto& elem : *p) { etl::destroy_at(etl::addressof(elem)); }
    } else {
        p->~T();
    }
}

} // namespace etl

#endif // TETL_MEMORY_DESTROY_AT_HPP