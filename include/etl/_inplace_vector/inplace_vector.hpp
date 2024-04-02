// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_INPLACE_VECTOR_INPLACE_VECTOR_HPP
#define TETL_INPLACE_VECTOR_INPLACE_VECTOR_HPP

#include <etl/_config/all.hpp>

#include <etl/_algorithm/copy.hpp>
#include <etl/_algorithm/move.hpp>
#include <etl/_array/uninitialized_array.hpp>
#include <etl/_cstddef/ptrdiff_t.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_iterator/next.hpp>
#include <etl/_iterator/prev.hpp>
#include <etl/_iterator/reverse_iterator.hpp>
#include <etl/_memory/ranges_construct_at.hpp>
#include <etl/_memory/ranges_destroy.hpp>
#include <etl/_memory/ranges_destroy_at.hpp>
#include <etl/_type_traits/conditional.hpp>
#include <etl/_type_traits/is_nothrow_copy_constructible.hpp>
#include <etl/_type_traits/is_nothrow_move_constructible.hpp>
#include <etl/_type_traits/is_trivially_copy_constructible.hpp>
#include <etl/_type_traits/is_trivially_destructible.hpp>
#include <etl/_type_traits/is_trivially_move_constructible.hpp>
#include <etl/_type_traits/smallest_size_t.hpp>
#include <etl/_utility/exchange.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/move.hpp>
#include <etl/_utility/unreachable.hpp>

namespace etl {

/// \headerfile etl/inplace_vector.hpp
/// \ingroup inplace_vector
template <typename T, etl::size_t Capacity>
struct inplace_vector {
    using value_type             = T;
    using size_type              = etl::size_t;
    using difference_type        = etl::ptrdiff_t;
    using reference              = value_type&;
    using const_reference        = value_type const&;
    using pointer                = T*;
    using const_pointer          = T const*;
    using iterator               = T*;
    using const_iterator         = T const*;
    using reverse_iterator       = etl::reverse_iterator<iterator>;
    using const_reverse_iterator = etl::reverse_iterator<const_iterator>;

    constexpr inplace_vector() = default;

    inplace_vector(inplace_vector const& other)
        requires etl::is_trivially_copy_constructible_v<T>
    = default;

    constexpr inplace_vector(inplace_vector const& other) noexcept(etl::is_nothrow_copy_constructible_v<T>)
    {
        etl::copy(other.begin(), other.end(), begin());
        _size = other._size; // NOLINT(cppcoreguidelines-prefer-member-initializer)
    }

    inplace_vector(inplace_vector&& other)
        requires etl::is_trivially_move_constructible_v<T>
    = default;

    constexpr inplace_vector(inplace_vector&& other) noexcept(etl::is_nothrow_move_constructible_v<T>)
    {
        etl::move(other.begin(), other.end(), begin());
        _size = etl::exchange(other._size, internal_size_t{}); // NOLINT(cppcoreguidelines-prefer-member-initializer)
    }

    ~inplace_vector()
        requires etl::is_trivially_destructible_v<T>
    = default;

    constexpr ~inplace_vector() { etl::ranges::destroy(*this); }

    [[nodiscard]] constexpr auto begin() const noexcept -> T const* { return data(); }

    [[nodiscard]] constexpr auto begin() noexcept -> T* { return data(); }

    [[nodiscard]] constexpr auto end() const noexcept -> T const*
    {
        return etl::next(begin(), static_cast<etl::ptrdiff_t>(size()));
    }

    [[nodiscard]] constexpr auto end() noexcept -> T*
    {
        return etl::next(begin(), static_cast<etl::ptrdiff_t>(size()));
    }

    [[nodiscard]] constexpr auto data() const noexcept -> T const* { return _storage.data(); }

    [[nodiscard]] constexpr auto data() noexcept -> T* { return _storage.data(); }

    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return size() == 0; }

    [[nodiscard]] constexpr auto size() const noexcept -> etl::size_t { return static_cast<etl::size_t>(_size); }

    [[nodiscard]] static constexpr auto capacity() noexcept -> etl::size_t { return Capacity; }

    [[nodiscard]] static constexpr auto max_size() noexcept -> etl::size_t { return Capacity; }

    [[nodiscard]] constexpr auto front() -> reference { return *begin(); }

    [[nodiscard]] constexpr auto front() const -> const_reference { return *begin(); }

    [[nodiscard]] constexpr auto back() -> reference { return *etl::prev(end()); }

    [[nodiscard]] constexpr auto back() const -> const_reference { return *etl::prev(end()); }

    [[nodiscard]] constexpr auto operator[](size_type n) -> reference
    {
        return *etl::next(data(), static_cast<etl::ptrdiff_t>(n));
    }

    [[nodiscard]] constexpr auto operator[](size_type n) const -> const_reference
    {
        return *etl::next(data(), static_cast<etl::ptrdiff_t>(n));
    }

    template <typename... Args>
    constexpr auto try_emplace_back(Args&&... args) -> T*
    {
        if (size() == capacity()) {
            return nullptr;
        }
        return etl::addressof(unchecked_emplace_back(TETL_FORWARD(args)...));
    }

    constexpr auto try_push_back(T const& val) -> T*
    {
        if (size() == capacity()) {
            return nullptr;
        }

        return etl::addressof(unchecked_push_back(val));
    }

    constexpr auto try_push_back(T&& val) -> T*
    {
        if (size() == capacity()) {
            return nullptr;
        }

        return etl::addressof(unchecked_push_back(TETL_MOVE(val)));
    }

    template <typename... Args>
    constexpr auto unchecked_emplace_back(Args&&... args) -> T&
    {
        etl::ranges::construct_at(end(), TETL_FORWARD(args)...);
        unsafe_set_size(size() + 1U);
        return back();
    }

    constexpr auto unchecked_push_back(T const& val) -> T&
    {
        etl::ranges::construct_at(end(), val);
        unsafe_set_size(size() + 1U);
        return back();
    }

    constexpr auto unchecked_push_back(T&& val) -> T&
    {
        etl::ranges::construct_at(end(), TETL_MOVE(val));
        unsafe_set_size(size() + 1U);
        return back();
    }

    constexpr auto pop_back() -> void
    {
        etl::ranges::destroy_at(etl::addressof(back()));
        unsafe_set_size(size() - 1U);
    }

    constexpr auto clear() noexcept -> void
    {
        etl::ranges::destroy(*this);
        unsafe_set_size(0);
    }

private:
    constexpr auto unsafe_set_size(size_type newSize) noexcept -> void
    {
        _size = static_cast<internal_size_t>(newSize);
    }

    using internal_size_t = etl::smallest_size_t<Capacity>;
    TETL_NO_UNIQUE_ADDRESS etl::uninitialized_array<T, Capacity> _storage;
    TETL_NO_UNIQUE_ADDRESS internal_size_t _size;
};

template <typename T>
struct inplace_vector<T, 0> {
    using value_type             = T;
    using size_type              = etl::size_t;
    using difference_type        = etl::ptrdiff_t;
    using reference              = value_type&;
    using const_reference        = value_type const&;
    using pointer                = T*;
    using const_pointer          = T const*;
    using iterator               = T*;
    using const_iterator         = T const*;
    using reverse_iterator       = etl::reverse_iterator<iterator>;
    using const_reverse_iterator = etl::reverse_iterator<const_iterator>;

    constexpr inplace_vector() = default;

    [[nodiscard]] constexpr auto begin() const noexcept -> T const* { return data(); }

    [[nodiscard]] constexpr auto begin() noexcept -> T* { return data(); }

    [[nodiscard]] constexpr auto end() const noexcept -> T const* { return nullptr; }

    [[nodiscard]] constexpr auto end() noexcept -> T* { return nullptr; }

    [[nodiscard]] constexpr auto data() const noexcept -> T const* { return nullptr; }

    [[nodiscard]] constexpr auto data() noexcept -> T* { return nullptr; }

    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return size() == 0; }

    [[nodiscard]] constexpr auto size() const noexcept -> etl::size_t { return 0; }

    [[nodiscard]] static constexpr auto capacity() noexcept -> etl::size_t { return 0; }

    [[nodiscard]] static constexpr auto max_size() noexcept -> etl::size_t { return 0; }

    [[nodiscard]] constexpr auto front() -> reference { etl::unreachable(); }

    [[nodiscard]] constexpr auto front() const -> const_reference { etl::unreachable(); }

    [[nodiscard]] constexpr auto back() -> reference { etl::unreachable(); }

    [[nodiscard]] constexpr auto back() const -> const_reference { etl::unreachable(); }

    [[nodiscard]] constexpr auto operator[](size_type /*n*/) -> reference { etl::unreachable(); }

    [[nodiscard]] constexpr auto operator[](size_type /*n*/) const -> const_reference { etl::unreachable(); }

    constexpr auto try_push_back(T const& /*val*/) -> T* { return nullptr; }

    constexpr auto try_push_back(T&& /*val*/) -> T* { return nullptr; }

    template <typename... Args>
    constexpr auto try_emplace_back(Args&&... /*args*/) -> T*
    {
        return nullptr;
    }

    constexpr auto unchecked_push_back(T const& /*val*/) -> T& { etl::unreachable(); }

    constexpr auto unchecked_push_back(T&& /*val*/) -> T& { etl::unreachable(); }

    template <typename... Args>
    constexpr auto unchecked_emplace_back(Args&&... /*args*/) -> T&
    {
        etl::unreachable();
    }

    constexpr auto pop_back() -> void { etl::unreachable(); }

    constexpr auto clear() noexcept -> void { }
};

} // namespace etl

#endif // TETL_INPLACE_VECTOR_INPLACE_VECTOR_HPP
