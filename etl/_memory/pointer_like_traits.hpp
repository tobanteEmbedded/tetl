/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_MEMORY_POINTER_LIKE_TRAITS_HPP
#define TETL_MEMORY_POINTER_LIKE_TRAITS_HPP

#include "etl/_cstddef/size_t.hpp"
#include "etl/_cstdint/uintptr_t.hpp"
#include "etl/_math/log2.hpp"

namespace etl {

/// \brief A traits type that is used to handle pointer types and things that
/// are just wrappers for pointers as a uniform entity.
/// \group pointer_like_traits
template <typename T>
struct pointer_like_traits;

/// \brief Provide pointer_like_traits for non-cvr pointers.
/// \group pointer_like_traits
template <typename T>
struct pointer_like_traits<T*> {
    [[nodiscard]] static auto get_as_void_pointer(T* p) -> void* { return p; }
    [[nodiscard]] static auto get_from_void_pointer(void* p) -> T* { return static_cast<T*>(p); }

    static constexpr size_t free_bits = detail::log2(alignof(T));
};

/// Provide pointer_like_traits for const things.
/// \group pointer_like_traits
template <typename T>
struct pointer_like_traits<const T> {
    using non_const = pointer_like_traits<T>;

    [[nodiscard]] static auto get_as_void_pointer(const T p) -> const void*
    {
        return non_const::get_as_void_pointer(p);
    }

    // NOLINTNEXTLINE(readability-const-return-type)
    [[nodiscard]] static auto get_from_void_pointer(const void* p) -> const T
    {
        return non_const::get_from_void_pointer(const_cast<void*>(p));
    }
    static constexpr size_t free_bits = non_const::free_bits;
};

/// Provide pointer_like_traits for const pointers.
/// \group pointer_like_traits
template <typename T>
struct pointer_like_traits<const T*> {
    using non_const = pointer_like_traits<T*>;

    [[nodiscard]] static auto get_as_void_pointer(const T* p) -> const void*
    {
        return non_const::get_as_void_pointer(const_cast<T*>(p));
    }
    [[nodiscard]] static auto get_from_void_pointer(const void* p) -> const T*
    {
        return non_const::get_from_void_pointer(const_cast<void*>(p));
    }
    static constexpr size_t free_bits = non_const::free_bits;
};

/// Provide pointer_like_traits for uintptr_t.
/// \group pointer_like_traits
template <>
struct pointer_like_traits<uintptr_t> {
    [[nodiscard]] static auto get_as_void_pointer(uintptr_t p) -> void* { return bit_cast<void*>(p); }
    [[nodiscard]] static auto get_from_void_pointer(void* p) -> uintptr_t { return bit_cast<uintptr_t>(p); }
    // No bits are available!
    static constexpr size_t free_bits = 0;
};

} // namespace etl

#endif // TETL_MEMORY_POINTER_LIKE_TRAITS_HPP