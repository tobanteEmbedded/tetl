// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_EXPECTED_EXPECTED_HPP
#define TETL_EXPECTED_EXPECTED_HPP

#include <etl/_concepts/same_as.hpp>
#include <etl/_expected/unexpect.hpp>
#include <etl/_expected/unexpected.hpp>
#include <etl/_type_traits/is_constructible.hpp>
#include <etl/_type_traits/is_default_constructible.hpp>
#include <etl/_type_traits/is_nothrow_constructible.hpp>
#include <etl/_type_traits/is_nothrow_default_constructible.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/in_place.hpp>
#include <etl/_utility/in_place_index.hpp>
#include <etl/_utility/move.hpp>
#include <etl/_variant/variant.hpp>

namespace etl {

template <typename T, typename E>
struct expected {
    // TODO: variant index doesn't work if same type is used twice
    static_assert(not etl::same_as<T, E>);

    using value_type      = T;
    using error_type      = E;
    using unexpected_type = etl::unexpected<E>;

    template <typename U>
    using rebind = etl::expected<U, error_type>;

    constexpr explicit expected() noexcept(etl::is_nothrow_default_constructible_v<T>)
        requires(etl::is_default_constructible_v<T>)
        : _u()
    {
    }

    template <typename... Args>
        requires etl::is_constructible_v<T, Args...>
    constexpr explicit expected(etl::in_place_t /*tag*/, Args&&... args)
        noexcept(etl::is_nothrow_constructible_v<T, Args...>)
        : _u(etl::in_place_index<0>, etl::forward<Args>(args)...)
    {
    }

    template <typename... Args>
        requires etl::is_constructible_v<E, Args...>
    constexpr explicit expected(etl::unexpect_t /*tag*/, Args&&... args)
        noexcept(etl::is_nothrow_constructible_v<E, Args...>)
        : _u(etl::in_place_index<1>, etl::forward<Args>(args)...)
    {
    }

    [[nodiscard]] constexpr explicit operator bool() const noexcept { return has_value(); }
    [[nodiscard]] constexpr auto has_value() const noexcept -> bool { return _u.index() == 0; }

    [[nodiscard]] constexpr auto operator->() const noexcept -> T const* { return etl::get_if<0>(&_u); }
    [[nodiscard]] constexpr auto operator->() noexcept -> T* { return etl::get_if<0>(&_u); }

    [[nodiscard]] constexpr auto operator*() const& noexcept -> T const& { return *etl::get_if<0>(&_u); }
    [[nodiscard]] constexpr auto operator*() & noexcept -> T& { return *etl::get_if<0>(&_u); }
    [[nodiscard]] constexpr auto operator*() const&& noexcept -> T const&& { return etl::move(*etl::get_if<0>(&_u)); }
    [[nodiscard]] constexpr auto operator*() && noexcept -> T&& { return etl::move(*etl::get_if<0>(&_u)); }

    [[nodiscard]] constexpr auto value() & -> T& { return etl::get<0>(_u); }
    [[nodiscard]] constexpr auto value() const& -> T const& { return etl::get<0>(_u); }
    [[nodiscard]] constexpr auto value() && -> T&& { return etl::get<0>(etl::move(_u)); }
    [[nodiscard]] constexpr auto value() const&& -> T const&& { return etl::get<0>(etl::move(_u)); }

    [[nodiscard]] constexpr auto error() & -> E& { return etl::get<1>(_u); }
    [[nodiscard]] constexpr auto error() const& -> E const& { return etl::get<1>(_u); }
    [[nodiscard]] constexpr auto error() && -> E&& { return etl::get<1>(etl::move(_u)); }
    [[nodiscard]] constexpr auto error() const&& -> E const&& { return etl::get<1>(etl::move(_u)); }

    template <typename U>
    [[nodiscard]] constexpr auto value_or(U&& fallback) const& -> T
    {
        return static_cast<bool>(*this) ? **this : static_cast<T>(etl::forward<U>(fallback));
    }

    template <typename U>
    [[nodiscard]] constexpr auto value_or(U&& fallback) && -> T
    {
        return static_cast<bool>(*this) ? etl::move(**this) : static_cast<T>(etl::forward<U>(fallback));
    }

private:
    etl::variant<T, E> _u;
};

} // namespace etl

#endif // TETL_EXPECTED_EXPECTED_HPP
