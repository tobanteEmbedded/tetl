// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_MEMORY_ALLOCATOR_TRAITS_HPP
#define TETL_MEMORY_ALLOCATOR_TRAITS_HPP

#include <etl/_memory/pointer_traits.hpp>
#include <etl/_type_traits/make_unsigned.hpp>

namespace etl {

namespace detail {

template <typename Alloc>
struct allocator_traits_pointer {
    using type = typename Alloc::value_type*;
};

template <typename Alloc>
    requires requires { typename Alloc::pointer; }
struct allocator_traits_pointer<Alloc> {
    using type = typename Alloc::pointer;
};

template <typename Alloc>
struct allocator_traits_const_pointer {
    using pointer = typename allocator_traits_pointer<Alloc>::type;
    using type    = typename etl::pointer_traits<pointer>::template rebind<typename Alloc::value_type const>;
};

template <typename Alloc>
    requires requires { typename Alloc::const_pointer; }
struct allocator_traits_const_pointer<Alloc> {
    using type = typename Alloc::const_pointer;
};

template <typename Alloc>
struct allocator_traits_void_pointer {
    using pointer = typename allocator_traits_pointer<Alloc>::type;
    using type    = typename etl::pointer_traits<pointer>::template rebind<void>;
};

template <typename Alloc>
    requires requires { typename Alloc::void_pointer; }
struct allocator_traits_void_pointer<Alloc> {
    using type = typename Alloc::void_pointer;
};

template <typename Alloc>
struct allocator_traits_const_void_pointer {
    using pointer = typename allocator_traits_pointer<Alloc>::type;
    using type    = typename etl::pointer_traits<pointer>::template rebind<void const>;
};

template <typename Alloc>
    requires requires { typename Alloc::const_void_pointer; }
struct allocator_traits_const_void_pointer<Alloc> {
    using type = typename Alloc::const_void_pointer;
};

template <typename Alloc>
struct allocator_traits_difference_type {
    using pointer = typename allocator_traits_pointer<Alloc>::type;
    using type    = typename etl::pointer_traits<pointer>::difference_type;
};

template <typename Alloc>
    requires requires { typename Alloc::difference_type; }
struct allocator_traits_difference_type<Alloc> {
    using type = typename Alloc::difference_type;
};

template <typename Alloc>
struct allocator_traits_size_type {
    using difference_type = typename allocator_traits_difference_type<Alloc>::type;
    using type            = etl::make_unsigned_t<difference_type>;
};

template <typename Alloc>
    requires requires { typename Alloc::size_type; }
struct allocator_traits_size_type<Alloc> {
    using type = typename Alloc::size_type;
};

} // namespace detail

template <typename Alloc>
struct allocator_traits {
    using allocator_type     = Alloc;
    using value_type         = typename Alloc::value_type;
    using pointer            = typename detail::allocator_traits_pointer<Alloc>::type;
    using const_pointer      = typename detail::allocator_traits_const_pointer<Alloc>::type;
    using void_pointer       = typename detail::allocator_traits_void_pointer<Alloc>::type;
    using const_void_pointer = typename detail::allocator_traits_const_void_pointer<Alloc>::type;
    using difference_type    = typename detail::allocator_traits_difference_type<Alloc>::type;
    using size_type          = typename detail::allocator_traits_size_type<Alloc>::type;

    [[nodiscard]] static constexpr auto allocate(Alloc& a, size_type n)
    {
        return a.allocate(n);
    }

    static constexpr void deallocate(Alloc& a, pointer p, size_type n)
    {
        a.deallocate(p, n);
    }
};

} // namespace etl

#endif // TETL_MEMORY_ALLOCATOR_TRAITS_HPP
