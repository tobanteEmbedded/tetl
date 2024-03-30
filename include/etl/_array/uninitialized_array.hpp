// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ARRAY_UNINITIALIZED_ARRAY_HPP
#define TETL_ARRAY_UNINITIALIZED_ARRAY_HPP

#include <etl/_config/all.hpp>

#include <etl/_array/c_array.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_iterator/data.hpp>
#include <etl/_iterator/size.hpp>
#include <etl/_type_traits/is_trivially_default_constructible.hpp>
#include <etl/_type_traits/is_trivially_destructible.hpp>

namespace etl {

namespace detail {
template <typename T>
concept sufficiently_trivial = etl::is_trivially_default_constructible_v<T> and etl::is_trivially_destructible_v<T>;
}

/// \headerfile etl/array
/// \ingroup array
template <typename T, etl::size_t Size>
struct uninitialized_array {
    using value_type = T;

    constexpr uninitialized_array() = default;

    [[nodiscard]] constexpr auto data() const noexcept -> T const* { return reinterpret_cast<T const*>(_storage); }

    [[nodiscard]] constexpr auto data() noexcept -> T* { return reinterpret_cast<T*>(_storage); }

    [[nodiscard]] static constexpr auto size() noexcept -> etl::size_t { return Size; }

private:
    alignas(T) TETL_NO_UNIQUE_ADDRESS etl::c_array<char, sizeof(T) * Size> _storage;
};

template <etl::detail::sufficiently_trivial T, etl::size_t Size>
    requires(Size != 0)
struct uninitialized_array<T, Size> {
    using value_type = T;

    constexpr uninitialized_array() = default;

    [[nodiscard]] constexpr auto data() const noexcept -> T const* { return static_cast<T const*>(_storage); }

    [[nodiscard]] constexpr auto data() noexcept -> T* { return static_cast<T*>(_storage); }

    [[nodiscard]] static constexpr auto size() noexcept -> etl::size_t { return Size; }

private:
    TETL_NO_UNIQUE_ADDRESS etl::c_array<T, Size> _storage;
};

template <typename T, etl::size_t Size>
    requires(Size == 0)
struct uninitialized_array<T, Size> {
    using value_type = T;

    constexpr uninitialized_array() = default;

    [[nodiscard]] constexpr auto data() const noexcept -> T const* { return nullptr; }

    [[nodiscard]] constexpr auto data() noexcept -> T* { return nullptr; }

    [[nodiscard]] static constexpr auto size() noexcept -> etl::size_t { return 0; }
};

} // namespace etl

#endif // TETL_ARRAY_UNINITIALIZED_ARRAY_HPP
