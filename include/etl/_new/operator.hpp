// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_NEW_OPERATOR_HPP
#define TETL_NEW_OPERATOR_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_utility/ignore_unused.hpp>

// Some parts of the new header are declared in the global namespace. To avoid
// ODR violations, we include the header <new> if it is available.
#if __has_include(<new>)
    #include <new>
#else

/// \brief Called by the standard single-object placement new expression. The
/// standard library implementation performs no action and returns ptr
/// unmodified. The behavior is undefined if this function is called through a
/// placement new expression and ptr is a null pointer.
[[nodiscard]] inline auto operator new(etl::size_t count, void* ptr) noexcept -> void*
{
    etl::ignore_unused(count);
    return ptr;
}

/// \brief Called by the standard array form placement new expression. The
/// standard library implementation performs no action and returns ptr
/// unmodified. The behavior is undefined if this function is called through a
/// placement new expression and ptr is a null pointer.
[[nodiscard]] inline auto operator new[](etl::size_t count, void* ptr) noexcept -> void*
{
    etl::ignore_unused(count);
    return ptr;
}

inline auto operator delete(void* /*ignore*/, void* /*ignore*/) noexcept -> void { }
inline auto operator delete[](void* /*ignore*/, void* /*ignore*/) noexcept -> void { }

#endif

#endif // TETL_NEW_OPERATOR_HPP
