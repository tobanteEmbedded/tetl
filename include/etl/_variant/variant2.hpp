// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_VARIANT_VARIANT2_HPP
#define TETL_VARIANT_VARIANT2_HPP

#include <etl/_config/all.hpp>

#include <etl/_cstddef/size_t.hpp>
#include <etl/_functional/equal_to.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_memory/destroy_at.hpp>
#include <etl/_meta/at.hpp>
#include <etl/_meta/count.hpp>
#include <etl/_meta/index_of.hpp>
#include <etl/_type_traits/add_pointer.hpp>
#include <etl/_type_traits/index_constant.hpp>
#include <etl/_type_traits/is_copy_constructible.hpp>
#include <etl/_type_traits/is_default_constructible.hpp>
#include <etl/_type_traits/is_move_constructible.hpp>
#include <etl/_type_traits/is_nothrow_copy_constructible.hpp>
#include <etl/_type_traits/is_nothrow_default_constructible.hpp>
#include <etl/_type_traits/is_nothrow_move_constructible.hpp>
#include <etl/_type_traits/is_trivially_copy_constructible.hpp>
#include <etl/_type_traits/is_trivially_move_constructible.hpp>
#include <etl/_type_traits/remove_cvref.hpp>
#include <etl/_type_traits/smallest_size_t.hpp>
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
    using first_type = etl::meta::at_t<0, etl::meta::list<Ts...>>;

public:
    constexpr variant2() noexcept(etl::is_nothrow_default_constructible_v<first_type>)
        requires(etl::is_default_constructible_v<first_type>)
        : variant2(etl::in_place_index<0>)
    {
    }

    template <etl::size_t I, typename... Args>
    explicit constexpr variant2(etl::in_place_index_t<I> /*index*/, Args&&... args)
        : _index(static_cast<index_type>(I))
        , _union(etl::index_v<I>, etl::forward<Args>(args)...)
    {
        static_assert(I < sizeof...(Ts));
    }

    template <typename T, typename... Args>
        requires(
            etl::is_constructible_v<T, Args...>
            and etl::meta::count_v<etl::remove_cvref_t<T>, etl::meta::list<Ts...>> == 1
        )
    explicit constexpr variant2(etl::in_place_type_t<T> /*tag*/, Args&&... args)
        : variant2(etl::in_place_index<etl::meta::index_of_v<T, etl::meta::list<Ts...>>>, etl::forward<Args>(args)...)
    {
    }

    constexpr variant2(variant2 const&) = default;

    constexpr variant2(variant2 const& /*other*/) noexcept((... and etl::is_nothrow_copy_constructible_v<Ts>))
        requires((... and etl::is_copy_constructible_v<Ts>) and !(... and etl::is_trivially_copy_constructible_v<Ts>))
    {
    }

    constexpr variant2(variant2&&) = default;

    constexpr variant2(variant2&& /*other*/) noexcept((... and etl::is_nothrow_move_constructible_v<Ts>))
        requires((... and etl::is_move_constructible_v<Ts>) and not(... and etl::is_trivially_move_constructible_v<Ts>))
    {
    }

    ~variant2()
        requires(... and etl::is_trivially_destructible_v<Ts>)
    = default;

    constexpr ~variant2()
    {
        etl::visit([](auto& v) { etl::destroy_at(etl::addressof(v)); }, *this);
    }

    /// \brief Returns the zero-based index of the alternative that is currently held by the variant.
    [[nodiscard]] constexpr auto index() const noexcept -> etl::size_t { return static_cast<etl::size_t>(_index); }

    /// \brief Returns a reference to the object stored in the variant.
    /// \pre v.index() == I
    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) & -> auto&
    {
        static_assert(I < sizeof...(Ts));
        return _union[index];
    }

    /// \brief Returns a reference to the object stored in the variant.
    /// \pre v.index() == I
    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) const& -> auto const&
    {
        static_assert(I < sizeof...(Ts));
        return _union[index];
    }

    /// \brief Returns a reference to the object stored in the variant.
    /// \pre v.index() == I
    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) && -> auto&&
    {
        static_assert(I < sizeof...(Ts));
        return etl::move(_union)[index];
    }

    /// \brief Returns a reference to the object stored in the variant.
    /// \pre v.index() == I
    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) const&& -> auto const&&
    {
        static_assert(I < sizeof...(Ts));
        return etl::move(_union)[index];
    }

    /// Equality operator for variants:
    ///
    /// - If lhs.index() != rhs.index(), returns false;
    /// - Otherwise returns get<lhs.index()>(lhs) == get<lhs.index()>(rhs)
    friend constexpr auto operator==(variant2 const& lhs, variant2 const& rhs) -> bool
    {
        if (lhs.index() != rhs.index()) {
            return false;
        }
        return etl::visit(etl::detail::make_variant_compare_op(etl::equal_to()), lhs, rhs);
    }

private:
    TETL_NO_UNIQUE_ADDRESS index_type _index;
    TETL_NO_UNIQUE_ADDRESS etl::variadic_union<Ts...> _union;
};

/// \brief Returns a reference to the object stored in the variant.
/// \pre v.index() == I
/// \relates variant2
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant2<Ts...>& v) -> auto&
{
    static_assert(I < sizeof...(Ts));
    return v[etl::index_v<I>];
}

/// \brief Returns a reference to the object stored in the variant.
/// \pre v.index() == I
/// \relates variant2
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant2<Ts...> const& v) -> auto const&
{
    static_assert(I < sizeof...(Ts));
    return v[etl::index_v<I>];
}

/// \brief Returns a reference to the object stored in the variant.
/// \pre v.index() == I
/// \relates variant2
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant2<Ts...>&& v) -> auto&&
{
    static_assert(I < sizeof...(Ts));
    return etl::move(v)[etl::index_v<I>];
}

/// \brief Returns a reference to the object stored in the variant.
/// \pre v.index() == I
/// \relates variant2
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant2<Ts...> const&& v) -> auto const&&
{
    static_assert(I < sizeof...(Ts));
    return etl::move(v)[etl::index_v<I>];
}

/// \brief If pv is not a null pointer and pv->index() == I, returns a pointer
///        to the value stored in the variant pointed to by pv. Otherwise, returns
///        a null pointer value. The call is ill-formed if I is not a valid index in the variant.
/// \relates variant2
template <etl::size_t I, typename... Ts>
constexpr auto get_if(variant2<Ts...>* pv
) noexcept -> etl::add_pointer_t<etl::variant_alternative_t<I, etl::variant2<Ts...>>>
{
    static_assert(I < sizeof...(Ts));
    if (pv == nullptr or pv->index() != I) {
        return nullptr;
    }
    return etl::addressof(etl::unchecked_get<I>(*pv));
}

/// \brief If pv is not a null pointer and pv->index() == I, returns a pointer
///        to the value stored in the variant pointed to by pv. Otherwise, returns
///        a null pointer value. The call is ill-formed if I is not a valid index in the variant.
/// \relates variant2
template <etl::size_t I, typename... Ts>
constexpr auto get_if(variant2<Ts...> const* pv
) noexcept -> etl::add_pointer_t<etl::variant_alternative_t<I, etl::variant2<Ts...>> const>
{
    static_assert(I < sizeof...(Ts));
    if (pv == nullptr or pv->index() != I) {
        return nullptr;
    }
    return etl::addressof(etl::unchecked_get<I>(*pv));
}

/// Type-based non-throwing accessor: The call is ill-formed if T is not a unique element of Ts....
/// \relates variant2
template <typename T, typename... Ts>
constexpr auto get_if(variant2<Ts...>* pv) noexcept -> add_pointer_t<T>
{
    return etl::get_if<etl::meta::index_of_v<T, etl::meta::list<Ts...>>>(pv);
}

/// Type-based non-throwing accessor: The call is ill-formed if T is not a unique element of Ts....
/// \relates variant2
template <typename T, typename... Ts>
constexpr auto get_if(variant2<Ts...> const* pv) noexcept -> add_pointer_t<T const>
{
    return etl::get_if<etl::meta::index_of_v<T, etl::meta::list<Ts...>>>(pv);
}

} // namespace etl

#endif // TETL_VARIANT_VARIANT2_HPP
