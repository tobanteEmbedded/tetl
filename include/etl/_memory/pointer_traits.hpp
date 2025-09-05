// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MEMORY_POINTER_TRAITS_HPP
#define TETL_MEMORY_POINTER_TRAITS_HPP

#include <etl/_cstddef/ptrdiff_t.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_type_traits/is_void.hpp>

namespace etl {

/// The pointer_traits class template provides the standardized way to
/// access certain properties of pointer-like types.
///
/// https://en.cppreference.com/w/cpp/memory/pointer_traits
template <typename Ptr>
struct pointer_traits {
    using pointer         = Ptr;
    using element_type    = typename Ptr::element_type;
    using difference_type = typename Ptr::difference_type;

    /// Constructs a dereferenceable pointer or pointer-like object
    /// ("fancy pointer") to its argument.
    ///
    /// \details
    /// https://en.cppreference.com/w/cpp/memory/pointer_traits/pointer_to
    ///
    /// \param r  Reference to an object of type element_type&.
    /// \returns A pointer to r, of the type pointer_traits::pointer.
    [[nodiscard]] static auto pointer_to(element_type& r) -> pointer
    {
        return Ptr::pointer_to(r);
    }
};

/// The pointer_traits class template provides the standardized way to
/// access certain properties of pointer-like types.
///
/// https://en.cppreference.com/w/cpp/memory/pointer_traits
///
/// \tparam T A raw pointer
template <typename T>
struct pointer_traits<T*> {
    using pointer         = T*;
    using element_type    = T;
    using difference_type = etl::ptrdiff_t;
    template <typename U>
    using rebind = U*;

    /// Constructs a dereferenceable pointer or pointer-like object
    /// ("fancy pointer") to its argument.
    ///
    /// https://en.cppreference.com/w/cpp/memory/pointer_traits/pointer_to
    ///
    /// \param r  Reference to an object of type element_type&.
    /// \returns A pointer to r, of the type pointer_traits::pointer.
    [[nodiscard]] static auto pointer_to(T& r) -> pointer
        requires(not etl::is_void_v<T>)
    {
        return etl::addressof(r);
    }
};

} // namespace etl

#endif // TETL_MEMORY_POINTER_TRAITS_HPP
