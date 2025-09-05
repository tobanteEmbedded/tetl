// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_EXPECTED_EXPECTED_HPP
#define TETL_EXPECTED_EXPECTED_HPP

#include <etl/_concepts/same_as.hpp>
#include <etl/_contracts/check.hpp>
#include <etl/_expected/unexpect.hpp>
#include <etl/_expected/unexpected.hpp>
#include <etl/_functional/invoke.hpp>
#include <etl/_type_traits/invoke_result.hpp>
#include <etl/_type_traits/is_constructible.hpp>
#include <etl/_type_traits/is_copy_constructible.hpp>
#include <etl/_type_traits/is_default_constructible.hpp>
#include <etl/_type_traits/is_move_constructible.hpp>
#include <etl/_type_traits/is_nothrow_constructible.hpp>
#include <etl/_type_traits/is_nothrow_copy_constructible.hpp>
#include <etl/_type_traits/is_nothrow_default_constructible.hpp>
#include <etl/_type_traits/is_nothrow_move_constructible.hpp>
#include <etl/_type_traits/is_trivially_copy_constructible.hpp>
#include <etl/_type_traits/is_trivially_move_constructible.hpp>
#include <etl/_type_traits/remove_cvref.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/in_place.hpp>
#include <etl/_utility/in_place_index.hpp>
#include <etl/_utility/move.hpp>
#include <etl/_variant/monostate.hpp>
#include <etl/_variant/variant.hpp>

namespace etl {

/// \ingroup expected
template <typename T, typename E>
struct expected {
    using value_type      = T;
    using error_type      = E;
    using unexpected_type = etl::unexpected<E>;

    template <typename U>
    using rebind = etl::expected<U, error_type>;

    /// Value-initializes member of type T.
    /// \post has_value() == true
    constexpr explicit expected() noexcept(is_nothrow_default_constructible_v<T>)
        requires(is_default_constructible_v<T>)
        : _u(in_place_index<1>)
    {
    }

    /// \post rhs.has_value() == this->has_value()
    constexpr expected(expected const& rhs) = default;

    /// \post rhs.has_value() == this->has_value()
    constexpr expected(
        expected const& rhs
    ) noexcept(etl::is_nothrow_copy_constructible_v<T> and etl::is_nothrow_copy_constructible_v<E>)
        requires(
            etl::is_copy_constructible_v<T> and etl::is_copy_constructible_v<E>
            and (not etl::is_trivially_copy_constructible_v<T> or not etl::is_trivially_copy_constructible_v<E>)
        )
        : _u(in_place_index<0>, etl::monostate{})
    {
        if (rhs.has_value()) {
            _u.template emplace<1>(*rhs);
        } else {
            _u.template emplace<2>(rhs.error());
        }
    }

    /// \post rhs.has_value() == this->has_value()
    constexpr expected(expected&& rhs) = default;

    /// \post rhs.has_value() == this->has_value()
    constexpr expected(
        expected&& rhs
    ) noexcept(etl::is_nothrow_move_constructible_v<T> and etl::is_nothrow_move_constructible_v<E>)
        requires(
            etl::is_move_constructible_v<T> and etl::is_move_constructible_v<E>
            and (not etl::is_trivially_move_constructible_v<T> or not etl::is_trivially_move_constructible_v<E>)
        )
        : _u(in_place_index<0>, etl::monostate{})
    {
        if (rhs.has_value()) {
            _u.template emplace<1>(etl::move(*rhs));
        } else {
            _u.template emplace<2>(etl::move(rhs.error()));
        }
    }

    ///
    template <typename... Args>
        requires is_constructible_v<T, Args...>
    constexpr explicit expected(in_place_t /*tag*/, Args&&... args) noexcept(is_nothrow_constructible_v<T, Args...>)
        : _u(in_place_index<1>, etl::forward<Args>(args)...)
    {
    }

    template <typename... Args>
        requires is_constructible_v<E, Args...>
    constexpr explicit expected(unexpect_t /*tag*/, Args&&... args) noexcept(is_nothrow_constructible_v<E, Args...>)
        : _u(in_place_index<2>, etl::forward<Args>(args)...)
    {
    }

    [[nodiscard]] constexpr explicit operator bool() const noexcept
    {
        return has_value();
    }

    [[nodiscard]] constexpr auto has_value() const noexcept -> bool
    {
        return _u.index() == 1;
    }

    [[nodiscard]] constexpr auto operator->() const noexcept -> T const*
    {
        return etl::get_if<1>(&_u);
    }

    [[nodiscard]] constexpr auto operator->() noexcept -> T*
    {
        return etl::get_if<1>(&_u);
    }

    [[nodiscard]] constexpr auto operator*() const& noexcept -> T const&
    {
        TETL_PRECONDITION(has_value());
        return _u[index_v<1>];
    }

    [[nodiscard]] constexpr auto operator*() & noexcept -> T&
    {
        TETL_PRECONDITION(has_value());
        return _u[index_v<1>];
    }

    [[nodiscard]] constexpr auto operator*() const&& noexcept -> T const&&
    {
        TETL_PRECONDITION(has_value());
        return etl::move(_u[index_v<1>]);
    }

    [[nodiscard]] constexpr auto operator*() && noexcept -> T&&
    {
        TETL_PRECONDITION(has_value());
        return etl::move(_u[index_v<1>]);
    }

    [[nodiscard]] constexpr auto error() & -> E&
    {
        TETL_PRECONDITION(not has_value());
        return _u[index_v<2>];
    }

    [[nodiscard]] constexpr auto error() const& -> E const&
    {
        TETL_PRECONDITION(not has_value());
        return _u[index_v<2>];
    }

    [[nodiscard]] constexpr auto error() && -> E&&
    {
        TETL_PRECONDITION(not has_value());
        return etl::move(_u[index_v<2>]);
    }

    [[nodiscard]] constexpr auto error() const&& -> E const&&
    {
        TETL_PRECONDITION(not has_value());
        return etl::move(_u[index_v<2>]);
    }

    template <typename... Args>
        requires is_nothrow_constructible_v<T, Args...>
    constexpr auto emplace(Args&&... args) noexcept -> T&
    {
        _u.template emplace<1>(etl::forward<Args>(args)...);
        return **this;
    }

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

    template <typename F>
    [[nodiscard]] constexpr auto and_then(F&& f) &
        requires(is_constructible_v<E, decltype(error())>)
    {
        if (has_value()) {
            return etl::invoke(etl::forward<F>(f), **this);
        }
        using U = remove_cvref_t<invoke_result_t<F, decltype(**this)>>;
        return U(unexpect, error());
    }

    template <typename F>
    [[nodiscard]] constexpr auto and_then(F&& f) &&
        requires(is_constructible_v<E, decltype(error())>)
    {
        if (has_value()) {
            return etl::invoke(etl::forward<F>(f), **this);
        }
        using U = remove_cvref_t<invoke_result_t<F, decltype(**this)>>;
        return U(unexpect, error());
    }

    template <typename F>
    [[nodiscard]] constexpr auto and_then(F&& f) const&
        requires(is_constructible_v<E, decltype(etl::move(error()))>)
    {
        if (has_value()) {
            return etl::invoke(etl::forward<F>(f), etl::move(**this));
        }
        using U = remove_cvref_t<invoke_result_t<F, decltype(etl::move(**this))>>;
        return U(unexpect, etl::move(error()));
    }

    template <typename F>
    [[nodiscard]] constexpr auto and_then(F&& f) const&&
        requires(is_constructible_v<E, decltype(etl::move(error()))>)
    {
        if (has_value()) {
            return etl::invoke(etl::forward<F>(f), etl::move(**this));
        }
        using U = remove_cvref_t<invoke_result_t<F, decltype(etl::move(**this))>>;
        return U(unexpect, etl::move(error()));
    }

    template <typename F>
    [[nodiscard]] constexpr auto or_else(F&& f) &
        requires(is_constructible_v<T, decltype(**this)>)
    {
        using G = remove_cvref_t<invoke_result_t<F, decltype(error())>>;
        if (has_value()) {
            return G(etl::in_place, **this);
        }
        return etl::invoke(etl::forward<F>(f), error());
    }

    template <typename F>
    [[nodiscard]] constexpr auto or_else(F&& f) &&
        requires(is_constructible_v<T, decltype(**this)>)
    {
        using G = remove_cvref_t<invoke_result_t<F, decltype(error())>>;
        if (has_value()) {
            return G(etl::in_place, **this);
        }
        return etl::invoke(etl::forward<F>(f), error());
    }

    template <typename F>
    [[nodiscard]] constexpr auto or_else(F&& f) const&
        requires(is_constructible_v<T, decltype(etl::move(**this))>)
    {
        using G = remove_cvref_t<invoke_result_t<F, decltype(etl::move(error()))>>;
        if (has_value()) {
            return G(etl::in_place, etl::move(**this));
        }
        return etl::invoke(etl::forward<F>(f), etl::move(error()));
    }

    template <typename F>
    [[nodiscard]] constexpr auto or_else(F&& f) const&&
        requires(is_constructible_v<T, decltype(etl::move(**this))>)
    {
        using G = remove_cvref_t<invoke_result_t<F, decltype(etl::move(error()))>>;
        if (has_value()) {
            return G(etl::in_place, etl::move(**this));
        }
        return etl::invoke(etl::forward<F>(f), etl::move(error()));
    }

private:
    etl::variant<etl::monostate, T, E> _u;
};

} // namespace etl

#endif // TETL_EXPECTED_EXPECTED_HPP
