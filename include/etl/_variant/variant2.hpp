// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_VARIANT_VARIANT2_HPP
#define TETL_VARIANT_VARIANT2_HPP

#include <etl/_config/all.hpp>

#include <etl/_cstddef/size_t.hpp>
#include <etl/_functional/equal_to.hpp>
#include <etl/_functional/greater.hpp>
#include <etl/_functional/greater_equal.hpp>
#include <etl/_functional/less.hpp>
#include <etl/_functional/less_equal.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_memory/construct_at.hpp>
#include <etl/_memory/destroy_at.hpp>
#include <etl/_meta/at.hpp>
#include <etl/_meta/count.hpp>
#include <etl/_meta/index_of.hpp>
#include <etl/_type_traits/add_pointer.hpp>
#include <etl/_type_traits/index_constant.hpp>
#include <etl/_type_traits/is_constructible.hpp>
#include <etl/_type_traits/is_copy_assignable.hpp>
#include <etl/_type_traits/is_copy_constructible.hpp>
#include <etl/_type_traits/is_default_constructible.hpp>
#include <etl/_type_traits/is_move_assignable.hpp>
#include <etl/_type_traits/is_move_constructible.hpp>
#include <etl/_type_traits/is_nothrow_copy_assignable.hpp>
#include <etl/_type_traits/is_nothrow_copy_constructible.hpp>
#include <etl/_type_traits/is_nothrow_default_constructible.hpp>
#include <etl/_type_traits/is_nothrow_move_assignable.hpp>
#include <etl/_type_traits/is_nothrow_move_constructible.hpp>
#include <etl/_type_traits/is_same.hpp>
#include <etl/_type_traits/is_trivially_copy_assignable.hpp>
#include <etl/_type_traits/is_trivially_copy_constructible.hpp>
#include <etl/_type_traits/is_trivially_move_assignable.hpp>
#include <etl/_type_traits/is_trivially_move_constructible.hpp>
#include <etl/_type_traits/remove_cvref.hpp>
#include <etl/_type_traits/smallest_size_t.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/in_place_index.hpp>
#include <etl/_utility/in_place_type.hpp>
#include <etl/_variant/variadic_union.hpp>
#include <etl/_variant/variant_alternative.hpp>
#include <etl/_variant/variant_alternative_selector.hpp>
#include <etl/_variant/variant_fwd.hpp>
#include <etl/_variant/variant_size.hpp>
#include <etl/_variant/visit.hpp>

namespace etl {

namespace detail {

template <typename T>
concept variant_copy_assignable = etl::is_copy_constructible_v<T> and etl::is_copy_assignable_v<T>;

template <typename T>
concept variant_trivially_copy_assignable
    = etl::is_trivially_copy_constructible_v<T> and etl::is_trivially_copy_assignable_v<T>;

template <typename T>
concept variant_move_assignable = etl::is_move_constructible_v<T> and etl::is_move_assignable_v<T>;

template <typename T>
concept variant_trivially_move_assignable
    = etl::is_trivially_move_constructible_v<T> and etl::is_trivially_move_assignable_v<T>;

template <typename T>
inline constexpr auto is_in_place_index = false;

template <size_t I>
inline constexpr auto is_in_place_index<etl::in_place_index_t<I>> = true;

template <typename T>
inline constexpr auto is_in_place_type = false;

template <typename T>
inline constexpr auto is_in_place_type<etl::in_place_type_t<T>> = true;

} // namespace detail

/// \ingroup variant
template <typename... Ts>
struct variant2 {
private:
    // Avoid valueless_by_exception
    static_assert((etl::is_nothrow_move_constructible_v<Ts> and ...));

    using index_type = etl::smallest_size_t<sizeof...(Ts)>;
    using first_type = etl::meta::at_t<0, etl::meta::list<Ts...>>;

public:
    constexpr variant2() noexcept(etl::is_nothrow_default_constructible_v<first_type>)
        requires(etl::is_default_constructible_v<first_type>)
        : variant2(etl::in_place_index<0>)
    {
    }

    // clang-format off
    template <typename T>
        requires (
                (sizeof...(Ts) > 0)
            and not etl::is_same_v<etl::remove_cvref_t<T>, variant2>
            and not etl::detail::is_in_place_index<etl::remove_cvref_t<T>>
            and not etl::detail::is_in_place_type<etl::remove_cvref_t<T>>
            and etl::is_constructible_v<etl::detail::variant_alternative_selector_t<T, Ts...>, T>
        )
    // clang-format on
    constexpr variant2(T&& t)
        noexcept(etl::is_nothrow_constructible_v<etl::detail::variant_alternative_selector_t<T, Ts...>, T>)
        : variant2(etl::in_place_type<etl::detail::variant_alternative_selector_t<T, Ts...>>, etl::forward<T>(t))
    {
    }

    template <etl::size_t I, typename... Args>
        requires((I < sizeof...(Ts)) and etl::is_constructible_v<etl::variant_alternative_t<I, variant2>, Args...>)
    explicit constexpr variant2(etl::in_place_index_t<I> /*index*/, Args&&... args)
        : _index(static_cast<index_type>(I))
        , _union(etl::index_v<I>, etl::forward<Args>(args)...)
    {
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

    constexpr variant2(variant2 const& other) noexcept((... and etl::is_nothrow_copy_constructible_v<Ts>))
        requires((... and etl::is_copy_constructible_v<Ts>) and !(... and etl::is_trivially_copy_constructible_v<Ts>))
        : variant2(other, copy_move_tag{})
    {
    }

    constexpr variant2(variant2&&) = default;

    constexpr variant2(variant2&& other) noexcept((... and etl::is_nothrow_move_constructible_v<Ts>))
        requires((... and etl::is_move_constructible_v<Ts>) and not(... and etl::is_trivially_move_constructible_v<Ts>))
        : variant2(etl::move(other), copy_move_tag{})
    {
    }

    constexpr auto operator=(variant2 const&) -> variant2& = default;

    constexpr auto operator=(variant2 const& other)
        noexcept((... and etl::is_nothrow_copy_assignable_v<Ts>) and (... and etl::is_nothrow_copy_constructible_v<Ts>))
            -> variant2&
        requires(
            (... and etl::detail::variant_copy_assignable<Ts>)
            and not(... and etl::detail::variant_trivially_copy_assignable<Ts>)
        )
    {
        assign(other);
        return *this;
    }

    constexpr auto operator=(variant2&&) -> variant2& = default;

    constexpr auto operator=(variant2&& other)
        noexcept((... and etl::is_nothrow_move_assignable_v<Ts>) and (... and etl::is_nothrow_move_constructible_v<Ts>))
            -> variant2&
        requires(
            (... and etl::detail::variant_move_assignable<Ts>)
            and !(... and etl::detail::variant_trivially_move_assignable<Ts>)
        )
    {
        assign(etl::move(other));
        return *this;
    }

    ~variant2()
        requires(... and etl::is_trivially_destructible_v<Ts>)
    = default;

    constexpr ~variant2() { destroy(); }

    /// Returns the zero-based index of the alternative that is currently held by the variant.
    [[nodiscard]] constexpr auto index() const noexcept -> etl::size_t { return static_cast<etl::size_t>(_index); }

    /// Returns a reference to the object stored in the variant.
    /// \pre v.index() == I
    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) & -> auto&
    {
        static_assert(I < sizeof...(Ts));
        return _union[index];
    }

    /// Returns a reference to the object stored in the variant.
    /// \pre v.index() == I
    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) const& -> auto const&
    {
        static_assert(I < sizeof...(Ts));
        return _union[index];
    }

    /// Returns a reference to the object stored in the variant.
    /// \pre v.index() == I
    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) && -> auto&&
    {
        static_assert(I < sizeof...(Ts));
        return etl::move(_union)[index];
    }

    /// Returns a reference to the object stored in the variant.
    /// \pre v.index() == I
    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) const&& -> auto const&&
    {
        static_assert(I < sizeof...(Ts));
        return etl::move(_union)[index];
    }

    template <typename T, typename... Args>
        requires(etl::is_constructible_v<T, Args...> and etl::meta::count_v<T, etl::meta::list<Ts...>> == 1)
    constexpr auto emplace(Args&&... args) -> auto&
    {
        destroy();
        return replace(etl::index_v<etl::meta::index_of_v<T, etl::meta::list<Ts...>>>, etl::forward<Args>(args)...);
    }

    template <etl::size_t I, typename... Args>
        requires etl::is_constructible_v<etl::meta::at_t<I, etl::meta::list<Ts...>>, Args...>
    constexpr auto emplace(Args&&... args) -> auto&
    {
        destroy();
        return replace(etl::index_v<I>, etl::forward<Args>(args)...);
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

    /// Less-than operator for variants:
    ///
    /// - If `lhs.index() < rhs.index()`, `returns true`;
    /// - If `lhs.index() > rhs.index()`, `returns false`;
    /// - Otherwise `returns get<lhs.index()>(v) < get<lhs.index()>(w)`
    friend constexpr auto operator<(variant2 const& lhs, variant2 const& rhs) -> bool
    {
        if (lhs.index() < rhs.index()) {
            return true;
        }
        if (lhs.index() > rhs.index()) {
            return false;
        }

        return etl::visit(etl::detail::make_variant_compare_op(etl::less()), lhs, rhs);
    }

    /// Less-equal operator for variants:
    ///
    /// - If lhs.index() < rhs.index(), returns true;
    /// - If lhs.index() > rhs.index(), returns false;
    /// - Otherwise returns get<lhs.index()>(v) <= get<lhs.index()>(w)
    friend constexpr auto operator<=(variant2 const& lhs, variant2 const& rhs) -> bool
    {
        if (lhs.index() < rhs.index()) {
            return true;
        }
        if (lhs.index() > rhs.index()) {
            return false;
        }

        return etl::visit(etl::detail::make_variant_compare_op(etl::less_equal()), lhs, rhs);
    }

    /// Greater-than operator for variants:
    ///
    /// - If lhs.index() > rhs.index(), returns true;
    /// - If lhs.index() < rhs.index(), returns false;
    /// - Otherwise returns get<lhs.index()>(v) > get<lhs.index()>(w)
    friend constexpr auto operator>(variant2 const& lhs, variant2 const& rhs) -> bool
    {
        if (lhs.index() > rhs.index()) {
            return true;
        }
        if (lhs.index() < rhs.index()) {
            return false;
        }

        return etl::visit(etl::detail::make_variant_compare_op(etl::greater()), lhs, rhs);
    }

    /// Greater-equal operator for variants:
    ///
    /// - If lhs.index() > rhs.index(), returns true;
    /// - If lhs.index() < rhs.index(), returns false;
    /// - Otherwise returns get<lhs.index()>(v) >= get<lhs.index()>(w)
    friend constexpr auto operator>=(variant2 const& lhs, variant2 const& rhs) -> bool
    {
        if (lhs.index() > rhs.index()) {
            return true;
        }
        if (lhs.index() < rhs.index()) {
            return false;
        }

        return etl::visit(etl::detail::make_variant_compare_op(etl::greater_equal()), lhs, rhs);
    }

private:
    struct copy_move_tag { };

    template <typename Other>
    constexpr variant2(Other&& other, [[maybe_unused]] copy_move_tag tag)
        : _index()
        , _union(etl::uninitialized_union())
    {
        etl::visit_with_index([&](auto param) {
            replace(param.index, etl::move(param).value());
        }, etl::forward<Other>(other));
    }

    template <typename Other>
    constexpr auto assign(Other&& other) -> void
    {
        etl::visit_with_index([&](auto lhs, auto rhs) {
            if constexpr (lhs.index == rhs.index) {
                lhs.value() = etl::move(rhs.value());
            } else {
                destroy();
                replace(rhs.index, etl::move(rhs.value()));
            }
        }, *this, etl::forward<Other>(other));
    }

    template <typename... Args>
    constexpr auto replace(auto index, Args&&... args) -> auto&
    {
        etl::construct_at(etl::addressof(_union), index, etl::forward<Args>(args)...);
        _index = static_cast<index_type>(index.value);
        return (*this)[index];
    }

    constexpr auto destroy() -> void
    {
        etl::visit([](auto& v) { etl::destroy_at(etl::addressof(v)); }, *this);
    }

    TETL_NO_UNIQUE_ADDRESS index_type _index;
    TETL_NO_UNIQUE_ADDRESS etl::variadic_union<Ts...> _union;
};

/// Checks if the variant v holds the alternative T. The call is
/// ill-formed if T does not appear exactly once in Ts...
/// \relates variant2
template <typename T, typename... Ts>
constexpr auto holds_alternative(variant2<Ts...> const& v) noexcept -> bool
{
    static_assert(etl::meta::count_v<T, etl::meta::list<Ts...>> == 1);
    return v.index() == etl::meta::index_of_v<T, etl::meta::list<Ts...>>;
}

/// Returns a reference to the object stored in the variant.
/// \pre v.index() == I
/// \relates variant2
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant2<Ts...>& v) -> auto&
{
    static_assert(I < sizeof...(Ts));
    return v[etl::index_v<I>];
}

/// Returns a reference to the object stored in the variant.
/// \pre v.index() == I
/// \relates variant2
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant2<Ts...> const& v) -> auto const&
{
    static_assert(I < sizeof...(Ts));
    return v[etl::index_v<I>];
}

/// Returns a reference to the object stored in the variant.
/// \pre v.index() == I
/// \relates variant2
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant2<Ts...>&& v) -> auto&&
{
    static_assert(I < sizeof...(Ts));
    return etl::move(v)[etl::index_v<I>];
}

/// Returns a reference to the object stored in the variant.
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
