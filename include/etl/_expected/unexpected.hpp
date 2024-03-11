// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_EXPECTED_UNEXPECTED_HPP
#define TETL_EXPECTED_UNEXPECTED_HPP

#include <etl/_type_traits/is_constructible.hpp>
#include <etl/_type_traits/is_nothrow_swappable.hpp>
#include <etl/_type_traits/is_same.hpp>
#include <etl/_type_traits/is_swappable.hpp>
#include <etl/_type_traits/remove_cvref.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/in_place.hpp>
#include <etl/_utility/move.hpp>
#include <etl/_utility/swap.hpp>

namespace etl {

template <typename E>
struct unexpected {
    template <typename Err = E>
        requires(not etl::is_same_v<etl::remove_cvref_t<Err>, unexpected>          //
                 and not etl::is_same_v<etl::remove_cvref_t<Err>, etl::in_place_t> //
                 and etl::is_constructible_v<E, Err>)
    constexpr explicit unexpected(Err&& e) : _unex(etl::forward<Err>(e))
    {
    }

    template <typename... Args>
        requires etl::is_constructible_v<E, Args...>
    constexpr explicit unexpected(etl::in_place_t /*tag*/, Args&&... args) : _unex(etl::forward<Args>(args)...)
    {
    }

    constexpr unexpected(unexpected const&) = default;
    constexpr unexpected(unexpected&&)      = default;

    constexpr auto operator=(unexpected const&) -> unexpected& = default;
    constexpr auto operator=(unexpected&&) -> unexpected&      = default;

    [[nodiscard]] constexpr auto error() const& noexcept -> E const& { return _unex; }
    [[nodiscard]] constexpr auto error() & noexcept -> E& { return _unex; }
    [[nodiscard]] constexpr auto error() const&& noexcept -> E const&& { return etl::move(_unex); }
    [[nodiscard]] constexpr auto error() && noexcept -> E&& { return etl::move(_unex); }

    constexpr auto swap(unexpected& other) noexcept(etl::is_nothrow_swappable_v<E>) -> void
    {
        using etl::swap;
        swap(error(), other.error());
    }

    template <typename E2>
    friend constexpr auto operator==(unexpected const& lhs, unexpected<E2> const& rhs) -> bool
    {
        return lhs.error() == rhs.error();
    }

    friend constexpr auto swap(unexpected& x, unexpected& y) noexcept(noexcept(x.swap(y))) -> void
        requires(etl::is_swappable_v<E>)
    {
        x.swap(y);
    }

private:
    E _unex;
};

template <typename E>
unexpected(E) -> unexpected<E>;

} // namespace etl
#endif // TETL_EXPECTED_UNEXPECTED_HPP
