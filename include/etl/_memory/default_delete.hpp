// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MEMORY_DEFAULT_DELETE_HPP
#define TETL_MEMORY_DEFAULT_DELETE_HPP

#include <etl/_config/all.hpp>

#include <etl/_type_traits/is_convertible.hpp>
#include <etl/_type_traits/is_function.hpp>
#include <etl/_type_traits/is_void.hpp>

namespace etl {

template <typename T>
struct default_delete {
    constexpr default_delete() noexcept = default;

    template <typename U>
        requires(is_convertible_v<U*, T*>)
    default_delete(default_delete<U> const& /*unused*/) noexcept
    {
    }

    auto operator()(T* ptr) const noexcept -> void { delete ptr; }

private:
    static_assert(!is_function_v<T>);
    static_assert(!is_void_v<T>);
    static_assert(sizeof(T));
};

template <typename T>
struct default_delete<T[]> {
    constexpr default_delete() noexcept = default;

    template <typename U>
        requires(is_convertible_v<U (*)[], T (*)[]>)
    default_delete(default_delete<U[]> const& /*unused*/) noexcept
    {
    }

    template <typename U>
        requires(is_convertible_v<U (*)[], T (*)[]>)
    auto operator()(U* ptr) const noexcept -> void
    {
        delete[] ptr;
    }

private:
    static_assert(sizeof(T));
    static_assert(not is_void_v<T>);
};

} // namespace etl

#endif // TETL_MEMORY_DEFAULT_DELETE_HPP
