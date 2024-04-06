// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_VARIANT_VARIANT_HPP
#define TETL_VARIANT_VARIANT_HPP

#include <etl/_array/array.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_exception/raise.hpp>
#include <etl/_functional/equal_to.hpp>
#include <etl/_functional/greater.hpp>
#include <etl/_functional/greater_equal.hpp>
#include <etl/_functional/less.hpp>
#include <etl/_functional/less_equal.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_memory/construct_at.hpp>
#include <etl/_memory/destroy_at.hpp>
#include <etl/_meta/at.hpp>
#include <etl/_meta/count.hpp>
#include <etl/_meta/index_of.hpp>
#include <etl/_new/operator.hpp>
#include <etl/_type_traits/add_pointer.hpp>
#include <etl/_type_traits/aligned_storage.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_type_traits/integral_constant.hpp>
#include <etl/_type_traits/is_default_constructible.hpp>
#include <etl/_type_traits/is_nothrow_default_constructible.hpp>
#include <etl/_type_traits/is_nothrow_move_constructible.hpp>
#include <etl/_type_traits/is_nothrow_swappable.hpp>
#include <etl/_type_traits/is_same.hpp>
#include <etl/_type_traits/is_trivially_destructible.hpp>
#include <etl/_type_traits/remove_cvref.hpp>
#include <etl/_type_traits/smallest_size_t.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/in_place_index.hpp>
#include <etl/_utility/in_place_type.hpp>
#include <etl/_utility/index_sequence.hpp>
#include <etl/_utility/move.hpp>
#include <etl/_utility/swap.hpp>
#include <etl/_variant/bad_variant_access.hpp>
#include <etl/_variant/monostate.hpp>
#include <etl/_variant/overload.hpp>
#include <etl/_variant/variant_alternative.hpp>
#include <etl/_variant/variant_fwd.hpp>
#include <etl/_variant/variant_size.hpp>
#include <etl/_variant/visit.hpp>

namespace etl {

namespace detail {

template <size_t Index, typename...>
struct variant_storage;

template <size_t Index, typename Head>
struct variant_storage<Index, Head> {
    using storage_t = aligned_storage_t<sizeof(Head), alignof(Head)>;
    storage_t data;

    template <typename T>
    constexpr auto construct(T&& head, size_t& index) -> void
    {
        new (&data) Head(etl::forward<T>(head));
        index = 0;
    }

    template <typename T, typename... Args>
    constexpr auto construct(in_place_type_t<T> /*tag*/, size_t& index, Args&&... args) -> void
    {
        new (&data) Head(etl::forward<Args>(args)...);
        index = 0;
    }

    constexpr auto destruct(size_t /*unused*/) -> void { static_cast<Head*>(static_cast<void*>(&data))->~Head(); }

    [[nodiscard]] constexpr auto get(index_constant<Index> /*ic*/) & -> Head& { return *to_ptr(); }

    [[nodiscard]] constexpr auto get(index_constant<Index> /*ic*/) const& -> Head const& { return *to_ptr(); }

    [[nodiscard]] constexpr auto get(index_constant<Index> /*ic*/) && -> Head&& { return etl::move(*to_ptr()); }

    [[nodiscard]] constexpr auto get(index_constant<Index> /*ic*/) const&& -> Head const&&
    {
        return etl::move(*to_ptr());
    }

    [[nodiscard]] constexpr auto to_ptr() noexcept -> Head* { return static_cast<Head*>(static_cast<void*>(&data)); }

    [[nodiscard]] constexpr auto to_ptr() const noexcept -> Head const*
    {
        return static_cast<Head const*>(static_cast<void const*>(&data));
    }
};

template <size_t Index, typename Head, typename... Tail>
struct variant_storage<Index, Head, Tail...> {
    using storage_t = aligned_storage_t<sizeof(Head), alignof(Head)>;

    union {
        storage_t data;
        variant_storage<Index + 1, Tail...> tail;
    };

    constexpr auto construct(Head const& head, size_t& index) -> void
    {
        new (&data) Head(head);
        index = 0;
    }

    constexpr auto construct(Head& head, size_t& index) -> void
    {
        auto const& headCref = head;
        construct(headCref, index);
    }

    constexpr auto construct(Head&& head, size_t& index) -> void
    {
        new (&data) Head(etl::move(head));
        index = 0;
    }

    template <typename... Args>
    constexpr auto construct(in_place_type_t<Head> /*tag*/, size_t& index, Args&&... args) -> void
    {
        new (&data) Head(etl::forward<Args>(args)...);
        index = 0;
    }

    template <typename T>
    constexpr auto construct(T&& t, size_t& index) -> void
    {
        tail.construct(etl::forward<T>(t), index);
        ++index;
    }

    template <typename T, typename... Args>
    constexpr auto construct(in_place_type_t<T> tag, size_t& index, Args&&... args) -> void
    {
        tail.construct(tag, index, etl::forward<Args>(args)...);
        ++index;
    }

    constexpr auto destruct(size_t index) -> void
    {
        if (index == 0) {
            static_cast<Head*>(static_cast<void*>(&data))->~Head();
            return;
        }

        tail.destruct(index - 1);
    }

    [[nodiscard]] constexpr auto get(index_constant<Index> /*ic*/) & -> Head& { return *to_ptr(); }

    [[nodiscard]] constexpr auto get(index_constant<Index> /*ic*/) const& -> Head const& { return *to_ptr(); }

    [[nodiscard]] constexpr auto get(index_constant<Index> /*ic*/) && -> Head&& { return etl::move(*to_ptr()); }

    [[nodiscard]] constexpr auto get(index_constant<Index> /*ic*/) const&& -> Head const&&
    {
        return etl::move(*to_ptr());
    }

    template <size_t N>
    [[nodiscard]] constexpr auto get(index_constant<N> ic) & -> auto&
    {
        return tail.get(ic);
    }

    template <size_t N>
    [[nodiscard]] constexpr auto get(index_constant<N> ic) const& -> auto const&
    {
        return tail.get(ic);
    }

    template <size_t N>
    [[nodiscard]] constexpr auto get(index_constant<N> ic) && -> auto&&
    {
        return etl::move(tail).get(ic);
    }

    template <size_t N>
    [[nodiscard]] constexpr auto get(index_constant<N> ic) const&& -> auto const&&
    {
        return etl::move(tail).get(ic);
    }

    [[nodiscard]] constexpr auto to_ptr() noexcept -> Head* { return static_cast<Head*>(static_cast<void*>(&data)); }

    [[nodiscard]] constexpr auto to_ptr() const noexcept -> Head const*
    {
        return static_cast<Head const*>(static_cast<void const*>(&data));
    }
};

template <typename... Ts>
using variant_storage_for = detail::variant_storage<0, Ts...>;

template <typename... Ts>
inline constexpr auto enable_variant_swap = ((etl::is_move_constructible_v<Ts> && etl::is_swappable_v<Ts>) && ...);

template <typename T>
struct variant_ctor_type_selector_single {
    auto operator()(T /*t*/) const -> T;
};

template <typename... Ts>
inline constexpr auto variant_ctor_type_selector = etl::overload{variant_ctor_type_selector_single<Ts>{}...};

template <typename T, typename... Ts>
using variant_ctor_type_selector_t = decltype(variant_ctor_type_selector<Ts...>(T()));

} // namespace detail

/// This is a special value equal to the largest value representable by the
/// type size_t, used as the return value of index() when valueless_by_exception() is true.
inline constexpr auto variant_npos = etl::numeric_limits<etl::size_t>::max();

/// The class template variant represents a type-safe union.
///
/// An instance of variant at any given time either holds a value of one of
/// its alternative types.
///
/// \warning All types need to be nothrow move constructible. This avoids the
/// need for valueless_by_exception.
///
/// \ingroup variant
template <typename... Ts>
struct variant {
private:
    // Avoid valueless_by_exception
    static_assert((etl::is_nothrow_move_constructible_v<Ts> and ...));

    using internal_size_t = etl::smallest_size_t<sizeof...(Ts)>;
    using first_type      = etl::meta::at_t<0, etl::meta::list<Ts...>>;

public:
    constexpr variant() noexcept(noexcept(etl::is_nothrow_default_constructible_v<first_type>))
        requires(etl::is_default_constructible_v<first_type>)
    {
        auto tmpIndex = etl::size_t{_index};
        _data.construct(in_place_type<first_type>, tmpIndex);
        _index = static_cast<internal_size_t>(tmpIndex);
    }

    /// (4) Converting constructor.
    ///
    /// Constructs a variant holding the alternative type T.
    ///
    /// https://en.cppreference.com/w/cpp/utility/variant/variant
    template <typename T>
    explicit variant(T&& t)
    {
        auto tmpIndex = size_t{_index};
        _data.construct(etl::forward<T>(t), tmpIndex);
        _index = static_cast<internal_size_t>(tmpIndex);
    }

    /// (5) Constructs a variant with the specified alternative T and
    /// initializes the contained value with the arguments
    /// etl::forward<Args>(args)....
    ///
    /// This overload participates in overload resolution only if there
    /// is exactly one occurrence of T in Ts... and
    /// is_constructible_v<T, Args...> is true.
    ///
    /// https://en.cppreference.com/w/cpp/utility/variant/variant
    ///
    /// \bug Improve sfinae (single unique type in variant)
    template <typename T, typename... Args>
        requires(etl::is_constructible_v<T, Args...>)
    constexpr explicit variant(etl::in_place_type_t<T> tag, Args&&... args)
    {
        auto tmpIndex = etl::size_t{_index};
        _data.construct(tag, tmpIndex, etl::forward<Args>(args)...);
        _index = static_cast<internal_size_t>(tmpIndex);
    }

    /// (7) Constructs a variant with the alternative T_i specified by
    /// the index I and initializes the contained value with the arguments
    /// etl::forward<Args>(args)...
    ///
    /// This overload participates in overload resolution only if I <
    /// sizeof...(Ts) and is_constructible_v<T_i, Args...> is true.
    ///
    /// https://en.cppreference.com/w/cpp/utility/variant/variant
    template <etl::size_t I, typename... Args>
        requires(I < sizeof...(Ts) and etl::is_constructible_v<etl::variant_alternative_t<I, variant>, Args...>)
    constexpr explicit variant(etl::in_place_index_t<I> /*tag*/, Args&&... args)
        : variant(in_place_type<etl::variant_alternative_t<I, variant>>, etl::forward<Args>(args)...)
    {
    }

    /// If valueless_by_exception is true, does nothing. Otherwise,
    /// destroys the currently contained value.
    constexpr ~variant()
        requires(etl::is_trivially_destructible_v<Ts> and ...)
    = default;

    constexpr ~variant()
    {
        etl::visit([](auto& v) { etl::destroy_at(etl::addressof(v)); }, *this);
    }

    constexpr auto operator=(variant const& rhs) -> variant&
    {
        // Self assignment
        if (this == &rhs) {
            return *this;
        }

        // Same type
        if (index() and rhs.index()) {
            _data = rhs._data;
            return *this;
        }

        return *this;
    }

    template <typename T>
        requires(not etl::is_same_v<etl::remove_cvref_t<T>, variant>
                 and etl::meta::count_v<etl::remove_cvref_t<T>, etl::meta::list<Ts...>> == 1)
    constexpr auto operator=(T&& rhs) -> variant&
    {
        auto v = variant(etl::in_place_type<T>, etl::forward<T>(rhs));
        v.swap(*this);
        return *this;
    }

    template <typename T, typename... Args>
    constexpr auto emplace(Args&&... args) -> T&;

    template <etl::size_t I, typename... Args>
    constexpr auto emplace(Args&&... args) -> etl::variant_alternative_t<I, variant>&;

    /// Returns the zero-based index of the alternative that is currently
    /// held by the variant. If the variant is valueless_by_exception, returns
    /// variant_npos.
    [[nodiscard]] constexpr auto index() const noexcept -> etl::size_t
    {
        return valueless_by_exception() ? variant_npos : _index;
    }

    /// Returns false if and only if the variant holds a value. Currently
    /// always returns false, since there is no default constructor.
    [[nodiscard]] constexpr auto valueless_by_exception() const noexcept -> bool { return false; }

    /// Swaps two variant objects.
    constexpr auto swap(variant& rhs)
        noexcept(((is_nothrow_move_constructible_v<Ts> && is_nothrow_swappable_v<Ts>) && ...)) -> void
    {
        if (index() == rhs.index()) {
            return etl::visit([](auto& l, auto& r) -> void {
                if constexpr (etl::is_same_v<decltype(l), decltype(r)>) {
                    using etl::swap;
                    swap(l, r);
                } else {
                    etl::unreachable();
                }
            }, *this, rhs);
        }

        etl::swap(_data, rhs._data);
        etl::swap(_index, rhs._index);
    }

    /// Returns a reference to the object stored in the variant.
    /// \pre I == index()
    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) & -> auto&
    {
        static_assert(I < sizeof...(Ts));
        return _data.get(index);
    }

    /// Returns a reference to the object stored in the variant.
    /// \pre I == index()
    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) const& -> auto const&
    {
        static_assert(I < sizeof...(Ts));
        return _data.get(index);
    }

    /// Returns a reference to the object stored in the variant.
    /// \pre I == index()
    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) && -> auto&&
    {
        static_assert(I < sizeof...(Ts));
        return etl::move(_data).get(index);
    }

    /// Returns a reference to the object stored in the variant.
    /// \pre I == index()
    template <etl::size_t I>
    constexpr auto operator[](etl::index_constant<I> index) const&& -> auto const&&
    {
        static_assert(I < sizeof...(Ts));
        return etl::move(_data).get(index);
    }

    /// Equality operator for variants:
    ///
    /// - If lhs.index() != rhs.index(), returns false;
    /// - If lhs.valueless_by_exception(), returns true;
    /// - Otherwise returns get<lhs.index()>(lhs) == get<lhs.index()>(rhs)
    friend constexpr auto operator==(variant const& lhs, variant const& rhs) -> bool
    {
        if (lhs.index() != rhs.index()) {
            return false;
        }

        return etl::visit(etl::detail::make_variant_compare_op(etl::equal_to()), lhs, rhs);
    }

    /// Less-than operator for variants:
    ///
    /// - If rhs.valueless_by_exception(), returns false;
    /// - If lhs.valueless_by_exception(), returns true;
    /// - If lhs.index() < rhs.index(), returns true;
    /// - If lhs.index() > rhs.index(), returns false;
    /// - Otherwise returns get<lhs.index()>(v) < get<lhs.index()>(w)
    friend constexpr auto operator<(variant const& lhs, variant const& rhs) -> bool
    {
        // if (rhs.valueless_by_exception()) { return false; }
        // if (lhs.valueless_by_exception()) { return true; }

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
    /// - If lhs.valueless_by_exception(), returns true;
    /// - If rhs.valueless_by_exception(), returns false;
    /// - If lhs.index() < rhs.index(), returns true;
    /// - If lhs.index() > rhs.index(), returns false;
    /// - Otherwise returns get<lhs.index()>(v) <= get<lhs.index()>(w)
    friend constexpr auto operator<=(variant const& lhs, variant const& rhs) -> bool
    {
        // if (lhs.valueless_by_exception()) { return true; }
        // if (rhs.valueless_by_exception()) { return false; }

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
    /// - If lhs.valueless_by_exception(), returns false;
    /// - If rhs.valueless_by_exception(), returns true;
    /// - If lhs.index() > rhs.index(), returns true;
    /// - If lhs.index() < rhs.index(), returns false;
    /// - Otherwise returns get<lhs.index()>(v) > get<lhs.index()>(w)
    friend constexpr auto operator>(variant const& lhs, variant const& rhs) -> bool
    {
        // if (lhs.valueless_by_exception()) { return false; }
        // if (rhs.valueless_by_exception()) { return true; }

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
    /// - If lhs.valueless_by_exception(), returns false;
    /// - If rhs.valueless_by_exception(), returns true;
    /// - If lhs.index() > rhs.index(), returns true;
    /// - If lhs.index() < rhs.index(), returns false;
    /// - Otherwise returns get<lhs.index()>(v) >= get<lhs.index()>(w)
    friend constexpr auto operator>=(variant const& lhs, variant const& rhs) -> bool
    {
        // if (lhs.valueless_by_exception()) { return false; }
        // if (rhs.valueless_by_exception()) { return true; }

        if (lhs.index() > rhs.index()) {
            return true;
        }
        if (lhs.index() < rhs.index()) {
            return false;
        }

        return etl::visit(etl::detail::make_variant_compare_op(etl::greater_equal()), lhs, rhs);
    }

private:
    etl::detail::variant_storage_for<Ts...> _data;
    internal_size_t _index{0};
};

/// Overloads the swap algorithm for variant. Effectively calls lhs.swap(rhs).
///
/// This overload participates in overload resolution only if is_move_constructible_v<T_i>
/// and is_swappable_v<T_i> are both true for all T_i in Ts...
template <typename... Ts>
    requires(detail::enable_variant_swap<Ts...>)
constexpr auto swap(variant<Ts...>& lhs, variant<Ts...>& rhs) noexcept(noexcept(lhs.swap(rhs))) -> void
{
    lhs.swap(rhs);
}

/// Checks if the variant v holds the alternative T. The call is
/// ill-formed if T does not appear exactly once in Ts...
template <typename T, typename... Ts>
constexpr auto holds_alternative(variant<Ts...> const& v) noexcept -> bool
{
    return v.index() == etl::meta::index_of_v<T, etl::meta::list<Ts...>>;
}

/// Returns a reference to the object stored in the variant.
/// \pre `v.index() == I`
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant<Ts...>& v) -> auto&
{
    return v[etl::index_v<I>];
}

/// Returns a reference to the object stored in the variant.
/// \pre `v.index() == I`
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant<Ts...> const& v) -> auto const&
{
    return v[etl::index_v<I>];
}

/// Returns a reference to the object stored in the variant.
/// \pre `v.index() == I`
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant<Ts...>&& v) -> auto&&
{
    return etl::move(v)[etl::index_v<I>];
}

/// Returns a reference to the object stored in the variant.
/// \pre `v.index() == I`
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant<Ts...> const&& v) -> auto const&&
{
    return etl::move(v)[etl::index_v<I>];
}

/// Type-based value accessor. Returns a reference to the object stored in the variant.
/// \pre `holds_alternative<T>(v) == true`
template <typename T, typename... Ts>
[[nodiscard]] constexpr auto unchecked_get(variant<Ts...>& v) -> T&
{
    return etl::unchecked_get<etl::meta::index_of_v<T, etl::meta::list<Ts...>>>(v);
}

/// Type-based value accessor. Returns a reference to the object stored in the variant.
/// \pre `holds_alternative<T>(v) == true`
template <typename T, typename... Ts>
[[nodiscard]] constexpr auto unchecked_get(variant<Ts...>&& v) -> T&&
{
    return etl::unchecked_get<etl::meta::index_of_v<T, etl::meta::list<Ts...>>>(etl::move(v));
}

/// Type-based value accessor. Returns a reference to the object stored in the variant.
/// \pre `holds_alternative<T>(v) == true`
template <typename T, typename... Ts>
[[nodiscard]] constexpr auto unchecked_get(variant<Ts...> const& v) -> T const&
{
    return etl::unchecked_get<etl::meta::index_of_v<T, etl::meta::list<Ts...>>>(v);
}

/// Type-based value accessor. Returns a reference to the object stored in the variant.
/// \pre `holds_alternative<T>(v) == true`
template <typename T, typename... Ts>
[[nodiscard]] constexpr auto unchecked_get(variant<Ts...> const&& v) -> T const&&
{
    return etl::unchecked_get<etl::meta::index_of_v<T, etl::meta::list<Ts...>>>(etl::move(v));
}

/// Index-based non-throwing accessor: If pv is not a null pointer and
/// pv->index() == I, returns a pointer to the value stored in the variant
/// pointed to by pv. Otherwise, returns a null pointer value. The call is
/// ill-formed if I is not a valid index in the variant.
template <etl::size_t I, typename... Ts>
constexpr auto get_if(variant<Ts...>* pv) noexcept -> add_pointer_t<variant_alternative_t<I, variant<Ts...>>>
{
    if (pv->index() != I) {
        return nullptr;
    }
    return etl::addressof(etl::unchecked_get<I>(*pv));
}

/// Index-based non-throwing accessor: If pv is not a null pointer and
/// pv->index() == I, returns a pointer to the value stored in the variant
/// pointed to by pv. Otherwise, returns a null pointer value. The call is
/// ill-formed if I is not a valid index in the variant.
template <size_t I, typename... Ts>
constexpr auto get_if(variant<Ts...> const* pv
) noexcept -> add_pointer_t<variant_alternative_t<I, variant<Ts...>> const>
{
    if (pv->index() != I) {
        return nullptr;
    }
    return etl::addressof(etl::unchecked_get<I>(*pv));
}

/// Type-based non-throwing accessor: The call is ill-formed if T is not
/// a unique element of Ts....
template <typename T, typename... Ts>
constexpr auto get_if(variant<Ts...>* pv) noexcept -> add_pointer_t<T>
{
    return etl::get_if<etl::meta::index_of_v<T, etl::meta::list<Ts...>>>(pv);
}

/// Type-based non-throwing accessor: The call is ill-formed if T is not
/// a unique element of Ts....
template <typename T, typename... Ts>
constexpr auto get_if(variant<Ts...> const* pv) noexcept -> add_pointer_t<T const>
{
    return etl::get_if<etl::meta::index_of_v<T, etl::meta::list<Ts...>>>(pv);
}

template <typename... Ts>
template <typename T, typename... Args>
constexpr auto variant<Ts...>::emplace(Args&&... args) -> T&
{
    auto v = variant(etl::in_place_type<T>, etl::forward<Args>(args)...);
    v.swap(*this);
    return *etl::get_if<T>(this);
}

template <typename... Ts>
template <etl::size_t I, typename... Args>
constexpr auto variant<Ts...>::emplace(Args&&... args) -> etl::variant_alternative_t<I, variant>&
{
    auto v = variant(etl::in_place_index<I>, etl::forward<Args>(args)...);
    v.swap(*this);
    return *etl::get_if<I>(this);
}

} // namespace etl

#endif // TETL_VARIANT_VARIANT_HPP
