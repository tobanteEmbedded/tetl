// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_VARIANT_VARIANT2_HPP
#define TETL_VARIANT_VARIANT2_HPP

#include <etl/_config/all.hpp>

#include <etl/_container/smallest_size_t.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_type_traits/integral_constant.hpp>
#include <etl/_type_traits/is_copy_constructible.hpp>
#include <etl/_type_traits/is_default_constructible.hpp>
#include <etl/_type_traits/is_move_constructible.hpp>
#include <etl/_type_traits/is_nothrow_copy_constructible.hpp>
#include <etl/_type_traits/is_nothrow_default_constructible.hpp>
#include <etl/_type_traits/is_nothrow_move_constructible.hpp>
#include <etl/_type_traits/is_trivially_copy_constructible.hpp>
#include <etl/_type_traits/is_trivially_move_constructible.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/in_place_index.hpp>
#include <etl/_variant/variadic_union.hpp>
#include <etl/_variant/visit.hpp>

namespace etl {

template <typename... Ts>
struct variant2 {
private:
    // Avoid valueless_by_exception
    static_assert((etl::is_nothrow_move_constructible_v<Ts> and ...));

    // TODO
    static_assert((etl::is_trivially_copy_constructible_v<Ts> and ...));
    static_assert((etl::is_trivially_move_constructible_v<Ts> and ...));

    using index_type = etl::smallest_size_t<sizeof...(Ts)>;
    using first_type = etl::type_pack_element_t<0, Ts...>;

public:
    constexpr variant2() noexcept(etl::is_nothrow_default_constructible_v<first_type>)
        requires(etl::is_default_constructible_v<first_type>)
        : variant2(etl::in_place_index<0>)
    {
    }

    template <etl::size_t I, typename... Args>
    constexpr explicit variant2(etl::in_place_index_t<I> /*index*/, Args&&... args)
        : _index(static_cast<index_type>(I))
        , _union(etl::index_c<I>, TETL_FORWARD(args)...)
    {
    }

    constexpr variant2(variant2 const&) = default;

    constexpr variant2(variant2 const& /*other*/) noexcept((... and std::is_nothrow_copy_constructible_v<Ts>))
        requires((... and etl::is_copy_constructible_v<Ts>) and !(... and etl::is_trivially_copy_constructible_v<Ts>))
    {
    }

    constexpr variant2(variant2&&) = default;

    constexpr variant2(variant2&& /*other*/) noexcept((... and std::is_nothrow_move_constructible_v<Ts>))
        requires((... and etl::is_move_constructible_v<Ts>) and not(... and etl::is_trivially_move_constructible_v<Ts>))
    {
    }

    ~variant2()
        requires(... and etl::is_trivially_destructible_v<Ts>)
    = default;

    constexpr ~variant2() { /* visit(*this, bounded::destroy);*/ }

    [[nodiscard]] constexpr auto index() const noexcept -> etl::size_t { return static_cast<etl::size_t>(_index); }

    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) & -> auto&
    {
        return _union[index];
    }

    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) const& -> auto const&
    {
        return _union[index];
    }

    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) && -> auto&&
    {
        return TETL_MOVE(_union)[index];
    }

    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) const&& -> auto const&&
    {
        return TETL_MOVE(_union)[index];
    }

private:
    TETL_NO_UNIQUE_ADDRESS index_type _index;
    TETL_NO_UNIQUE_ADDRESS etl::variadic_union<Ts...> _union;
};

/// \brief Returns a reference to the object stored in the variant.
/// \pre v.index() == I
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant2<Ts...>& v) -> variant_alternative_t<I, variant2<Ts...>>&
{
    return v[etl::index_c<I>];
}

/// \brief Returns a reference to the object stored in the variant.
/// \pre v.index() == I
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant2<Ts...> const& v) -> variant_alternative_t<I, variant2<Ts...>> const&
{
    return v[etl::index_c<I>];
}

/// \brief Returns a reference to the object stored in the variant.
/// \pre v.index() == I
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant2<Ts...>&& v) -> variant_alternative_t<I, variant2<Ts...>>&&
{
    return TETL_MOVE(v)[etl::index_c<I>];
}

/// \brief Returns a reference to the object stored in the variant.
/// \pre v.index() == I
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant2<Ts...> const&& v) -> variant_alternative_t<I, variant2<Ts...>> const&&
{
    return TETL_MOVE(v)[etl::index_c<I>];
}

} // namespace etl

#endif // TETL_VARIANT_VARIANT2_HPP
