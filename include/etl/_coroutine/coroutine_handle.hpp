// SPDX-License-Identifier: BSL-1.0

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

    constexpr coroutine_handle(nullptr_t handle) noexcept : _handle(handle) { }

    constexpr auto operator=(nullptr_t) noexcept -> coroutine_handle&
    {
        _handle = nullptr;
        return *this;
    }

    [[nodiscard]] constexpr auto address() const noexcept -> void* { return _handle; }

    [[nodiscard]] static constexpr auto from_address(void* addr) noexcept -> coroutine_handle
    {
        auto self    = coroutine_handle {};
        self._handle = addr;
        return self;
    }

    [[nodiscard]] constexpr explicit operator bool() const noexcept { return _handle != nullptr; }

    [[nodiscard]] auto done() const noexcept -> bool { return __builtin_coro_done(_handle); }

    auto operator()() const -> void { resume(); }

    auto resume() const -> void { __builtin_coro_resume(_handle); }

    auto destroy() const -> void { __builtin_coro_destroy(_handle); }

protected:
    void* _handle {nullptr};
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
