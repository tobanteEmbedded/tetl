// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ARRAY_DYNAMIC_ARRAY_HPP
#define TETL_ARRAY_DYNAMIC_ARRAY_HPP

#include <etl/_config/all.hpp>

#include <etl/_cstddef/ptrdiff_t.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_iterator/next.hpp>
#include <etl/_memory/allocator_traits.hpp>
#include <etl/_memory/destroy.hpp>
#include <etl/_memory/uninitialized_fill.hpp>
#include <etl/_type_traits/is_default_constructible.hpp>
#include <etl/_utility/exchange.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

template <typename T, typename Allocator>
struct dynamic_array {
    using value_type      = T;
    using allocator_type  = Allocator;
    using size_type       = etl::size_t;
    using difference_type = etl::ptrdiff_t;
    using pointer         = T*;
    using const_pointer   = T const*;

    dynamic_array()
        requires(etl::is_default_constructible_v<Allocator>)
    = default;

    explicit dynamic_array(Allocator alloc) : _alloc{etl::move(alloc)} { }

    dynamic_array(etl::size_t n, T const& value, Allocator alloc = Allocator()) : _size{n}, _alloc{etl::move(alloc)}
    {
        _ptr = etl::allocator_traits<Allocator>::allocate(_alloc, n);
        etl::uninitialized_fill(begin(), end(), value);
    }

    explicit dynamic_array(etl::size_t n, Allocator alloc = Allocator()) : dynamic_array{n, T(), etl::move(alloc)} { }

    dynamic_array(dynamic_array const& other)                    = delete;
    auto operator=(dynamic_array const& other) -> dynamic_array& = delete;

    dynamic_array(dynamic_array&& other) noexcept
        : _ptr{etl::exchange(other._ptr, nullptr)}
        , _size{etl::exchange(other._size, 0)}
        , _alloc{etl::exchange(other._alloc, Allocator{})}
    {
    }

    auto operator=(dynamic_array&& other) noexcept -> dynamic_array&
    {
        _ptr   = etl::exchange(other._ptr, nullptr);
        _size  = etl::exchange(other._size, 0);
        _alloc = etl::exchange(other._alloc, Allocator{});
        return *this;
    }

    ~dynamic_array()
    {
        etl::destroy(begin(), end());
        etl::allocator_traits<Allocator>::deallocate(_alloc, _ptr, size());
    }

    [[nodiscard]] auto size() -> etl::size_t { return _size; }

    [[nodiscard]] auto size() const -> etl::size_t { return _size; }

    [[nodiscard]] auto data() -> T* { return _ptr; }

    [[nodiscard]] auto data() const -> T const* { return _ptr; }

    [[nodiscard]] auto begin() -> T* { return _ptr; }

    [[nodiscard]] auto begin() const -> T const* { return _ptr; }

    [[nodiscard]] auto end() -> T* { return etl::next(_ptr, static_cast<etl::ptrdiff_t>(size())); }

    [[nodiscard]] auto end() const -> T const* { return etl::next(_ptr, static_cast<etl::ptrdiff_t>(size())); }

private:
    T* _ptr{nullptr};
    etl::size_t _size{0};
    TETL_NO_UNIQUE_ADDRESS Allocator _alloc;
};

} // namespace etl

#endif // TETL_ARRAY_DYNAMIC_ARRAY_HPP
