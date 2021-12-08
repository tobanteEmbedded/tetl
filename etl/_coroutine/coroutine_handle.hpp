/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COROUTINE_COROUTINE_HANDLE_HPP
#define TETL_COROUTINE_COROUTINE_HANDLE_HPP

#include "etl/_cstddef/nullptr_t.hpp"
#include "etl/_functional/hash.hpp"

#if defined(__cpp_coroutines)

namespace etl {

template <typename Promise = void>
struct coroutine_handle;

template <>
struct coroutine_handle<void> {
    constexpr coroutine_handle() noexcept = default;

    constexpr coroutine_handle(nullptr_t handle) noexcept : handle_(handle) { }

    constexpr auto operator=(nullptr_t) noexcept -> coroutine_handle&
    {
        handle_ = nullptr;
        return *this;
    }

    [[nodiscard]] constexpr auto address() const noexcept -> void* { return handle_; }

    [[nodiscard]] constexpr static auto from_address(void* addr) noexcept -> coroutine_handle
    {
        auto self    = coroutine_handle {};
        self.handle_ = addr;
        return self;
    }

    [[nodiscard]] constexpr explicit operator bool() const noexcept { return handle_ != nullptr; }

    [[nodiscard]] auto done() const noexcept -> bool { return __builtin_coro_done(handle_); }

    auto operator()() const -> void { resume(); }

    auto resume() const -> void { __builtin_coro_resume(handle_); }

    auto destroy() const -> void { __builtin_coro_destroy(handle_); }

protected:
    void* handle_ { nullptr };
};

template <typename T>
struct hash<coroutine_handle<T>> {
    [[nodiscard]] auto operator()(coroutine_handle<T> const& v) const noexcept -> size_t
    {
        return hash<void*>()(v.address());
    }
};

} // namespace etl

#endif // defined(__cpp_coroutines)

#endif // TETL_COROUTINE_COROUTINE_HANDLE_HPP