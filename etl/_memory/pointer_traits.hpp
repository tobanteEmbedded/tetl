/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MEMORY_POINTER_TRAITS_HPP
#define TETL_MEMORY_POINTER_TRAITS_HPP

#include "etl/_cstddef/ptrdiff_t.hpp"

namespace etl {

/// \brief The pointer_traits class template provides the standardized way to
/// access certain properties of pointer-like types.
///
/// https://en.cppreference.com/w/cpp/memory/pointer_traits
///
/// \group pointer_traits
template <typename Ptr>
struct pointer_traits {
    using pointer         = Ptr;
    using element_type    = typename Ptr::element_type;
    using difference_type = typename Ptr::difference_type;

    /// \brief Constructs a dereferenceable pointer or pointer-like object
    /// ("fancy pointer") to its argument.
    /// https://en.cppreference.com/w/cpp/memory/pointer_traits/pointer_to
    /// \param r  Reference to an object of type element_type&.
    /// \returns A pointer to r, of the type pointer_traits::pointer.
    [[nodiscard]] static auto pointer_to(element_type& r) -> pointer
    {
        return Ptr::pointer_to(r);
    }
};

/// \brief The pointer_traits class template provides the standardized way to
/// access certain properties of pointer-like types.
/// https://en.cppreference.com/w/cpp/memory/pointer_traits
/// \tparam T A raw pointer
/// \group pointer_traits
template <typename T>
struct pointer_traits<T*> {
    using pointer         = T*;
    using element_type    = T;
    using difference_type = etl::ptrdiff_t;
    template <typename U>
    using rebind = U*;

    /// \brief Constructs a dereferenceable pointer or pointer-like object
    /// ("fancy pointer") to its argument.
    /// \param r  Reference to an object of type element_type&.
    /// \returns A pointer to r, of the type pointer_traits::pointer.
    /// https://en.cppreference.com/w/cpp/memory/pointer_traits/pointer_to
    [[nodiscard]] static auto pointer_to(element_type& r) -> pointer
    {
        return addressof(r);
    }
};

} // namespace etl

#endif // TETL_MEMORY_POINTER_TRAITS_HPP