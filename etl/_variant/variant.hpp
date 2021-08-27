/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_VARIANT_VARIANT_HPP
#define TETL_VARIANT_VARIANT_HPP

#include "etl/_array/array.hpp"
#include "etl/_concepts/requires.hpp"
#include "etl/_container/smallest_size_t.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_functional/equal_to.hpp"
#include "etl/_functional/greater.hpp"
#include "etl/_functional/greater_equal.hpp"
#include "etl/_functional/less.hpp"
#include "etl/_functional/less_equal.hpp"
#include "etl/_new/operator.hpp"
#include "etl/_type_traits/add_pointer.hpp"
#include "etl/_type_traits/aligned_storage.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/integral_constant.hpp"
#include "etl/_type_traits/is_nothrow_move_constructible.hpp"
#include "etl/_type_traits/is_nothrow_swappable.hpp"
#include "etl/_type_traits/is_same.hpp"
#include "etl/_type_traits/type_pack_element.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/index_sequence.hpp"
#include "etl/_utility/move.hpp"
#include "etl/_utility/swap.hpp"
#include "etl/_variant/monostate.hpp"
#include "etl/_variant/variant_alternative.hpp"
#include "etl/_variant/variant_fwd.hpp"
#include "etl/_variant/variant_size.hpp"
#include "etl/_warning/ignore_unused.hpp"

namespace etl {

namespace detail {

// swap
template <typename Variant>
using variant_swap_func_t = void (*)(Variant&, Variant&);

template <typename Variant, etl::size_t Index>
constexpr auto variant_swap_func(Variant& lhs, Variant& rhs) -> void
{
    using etl::swap;
    swap(*etl::get_if<Index>(&lhs), *etl::get_if<Index>(&rhs));
}

template <typename Variant, etl::size_t... Indices>
constexpr auto make_variant_swap_table(etl::index_sequence<Indices...> /*is*/)
{
    return etl::array { &variant_swap_func<Variant, Indices>... };
}

template <typename Variant, typename... Ts>
inline constexpr auto variant_swap_table
    = make_variant_swap_table<Variant>(etl::index_sequence_for<Ts...> {});

// compare
template <typename Variant>
using variant_cmp_func_t = bool (*)(Variant const&, Variant const&);

template <typename Op, typename Variant, etl::size_t Index>
constexpr auto variant_compare_func(Variant const& l, Variant const& r) -> bool
{
    return Op {}(*etl::get_if<Index>(&l), *etl::get_if<Index>(&r));
}

template <typename Op, typename Variant, etl::size_t... Indices>
constexpr auto make_variant_compare_table(
    etl::index_sequence<Indices...> /*is*/)
{
    return etl::array { &variant_compare_func<Op, Variant, Indices>... };
}

template <typename Op, typename Variant, typename... Ts>
inline constexpr auto variant_compare_table
    = make_variant_compare_table<Op, Variant>(
        etl::index_sequence_for<Ts...> {});

template <etl::size_t Index, typename...>
struct variant_storage;

template <etl::size_t Index, typename Head>
struct variant_storage<Index, Head> {
    using storage_t = etl::aligned_storage_t<sizeof(Head), alignof(Head)>;
    storage_t data;

    template <typename T>
    constexpr auto construct(T&& head, etl::size_t& index) -> void
    {
        static_assert(etl::is_same_v<T, Head>,
            "Tried to access non-existent type in union");
        new (&data) Head(etl::forward<T>(head));
        index = 0;
    }

    constexpr auto destruct(etl::size_t /*unused*/) -> void
    {
        static_cast<Head*>(static_cast<void*>(&data))->~Head();
    }

    [[nodiscard]] constexpr auto get_index(Head const& /*head*/) const
        -> etl::integral_constant<etl::size_t, Index>
    {
        return {};
    }

    [[nodiscard]] constexpr auto get_value(
        etl::integral_constant<etl::size_t, Index> /*ic*/) -> Head&
    {
        return *static_cast<Head*>(static_cast<void*>(&data));
    }

    [[nodiscard]] constexpr auto get_value(
        etl::integral_constant<etl::size_t, Index> /*ic*/) const -> Head const&
    {
        return *static_cast<Head const*>(static_cast<void const*>(&data));
    }
};

template <etl::size_t Index, typename Head, typename... Tail>
struct variant_storage<Index, Head, Tail...> {
    using storage_t = etl::aligned_storage_t<sizeof(Head), alignof(Head)>;

    union {
        storage_t data;
        variant_storage<Index + 1, Tail...> tail;
    };

    constexpr auto construct(Head const& head, etl::size_t& index) -> void
    {
        new (&data) Head(head);
        index = 0;
    }

    constexpr auto construct(Head& head, etl::size_t& index) -> void
    {
        const auto& headCref = head;
        construct(headCref, index);
    }

    constexpr auto construct(Head&& head, etl::size_t& index) -> void
    {
        using etl::move;
        new (&data) Head(move(head));
        index = 0;
    }

    template <typename T>
    constexpr auto construct(T&& t, etl::size_t& index) -> void
    {
        tail.construct(etl::forward<T>(t), index);
        ++index;
    }

    constexpr auto destruct(etl::size_t index) -> void
    {
        if (index == 0) {
            static_cast<Head*>(static_cast<void*>(&data))->~Head();
            return;
        }

        tail.destruct(index - 1);
    }

    [[nodiscard]] constexpr auto get_index(Head const& /*head*/) const
        -> etl::integral_constant<etl::size_t, Index>
    {
        return {};
    }

    template <typename T>
    [[nodiscard]] constexpr auto get_index(T const& t) const
    {
        return tail.get_index(t);
    }

    [[nodiscard]] constexpr auto get_value(
        etl::integral_constant<etl::size_t, Index> /*ic*/) -> Head&
    {
        return *static_cast<Head*>(static_cast<void*>(&data));
    }

    [[nodiscard]] constexpr auto get_value(
        etl::integral_constant<etl::size_t, Index> /*ic*/) const -> Head const&
    {
        return *static_cast<Head const*>(static_cast<void const*>(&data));
    }

    template <etl::size_t N>
    [[nodiscard]] constexpr auto get_value(
        etl::integral_constant<etl::size_t, N> ic) -> auto&
    {
        return tail.get_value(ic);
    }

    template <etl::size_t N>
    [[nodiscard]] constexpr auto get_value(
        etl::integral_constant<etl::size_t, N> ic) const -> auto const&
    {
        return tail.get_value(ic);
    }
};

template <typename... Ts>
using variant_storage_for = detail::variant_storage<0, Ts...>;

template <typename... Ts>
inline constexpr auto enable_variant_swap
    = ((is_move_constructible_v<Ts> && is_swappable_v<Ts>)&&...);

} // namespace detail

/// \brief This is a special value equal to the largest value representable by
/// the type etl::size_t, used as the return value of index() when
/// valueless_by_exception() is true.
inline constexpr auto variant_npos = static_cast<etl::size_t>(-1);

/// \brief The class template etl::variant represents a type-safe union. An
/// instance of etl::variant at any given time either holds a value of one of
/// its alternative types.
template <typename... Types>
struct variant {
private:
    using internal_size_t = etl::smallest_size_t<sizeof...(Types)>;

public:
    /// \brief Converting constructor.
    /// \details Constructs a variant holding the alternative type T.
    template <typename T>
    explicit variant(T&& t)
    {
        auto tmpIndex = etl::size_t { index_ };
        data_.construct(etl::forward<T>(t), tmpIndex);
        index_ = static_cast<internal_size_t>(tmpIndex);
    }

    /// \brief If valueless_by_exception is true, does nothing. Otherwise,
    /// destroys the currently contained value.
    /// \todo This destructor is trivial if
    /// etl::is_trivially_destructible_v<T_i> is true for all T_i in Types...
    ~variant()
    {
        if (!valueless_by_exception()) { data_.destruct(index_); }
    }

    /// \brief Copy-assignment
    /// \details  If both *this and rhs are valueless by exception, does
    /// nothing. Otherwise, if rhs holds the same alternative as *this, assigns
    /// the value contained in rhs to the value contained in *this. If an
    /// exception is thrown, *this does not become valueless: the value depends
    /// on the exception safety guarantee of the alternative's copy assignment.
    constexpr auto operator=(variant const& rhs) -> variant&
    {
        // Self assignment
        if (this == &rhs) { return *this; }

        // Same type
        if (index() && rhs.index()) {
            data_ = rhs.data_;
            return *this;
        }

        return *this;
    }

    /// \brief Returns the zero-based index of the alternative that is currently
    /// held by the variant. If the variant is valueless_by_exception, returns
    /// variant_npos.
    [[nodiscard]] constexpr auto index() const noexcept -> etl::size_t
    {
        return valueless_by_exception() ? variant_npos : index_;
    }

    /// \brief Returns false if and only if the variant holds a value. Currently
    /// always returns false, since there is no default constructor.
    [[nodiscard]] constexpr auto valueless_by_exception() const noexcept -> bool
    {
        return false;
    }

    static constexpr auto is_swap_noexcept
        = ((etl::is_nothrow_move_constructible_v<
                Types> && etl::is_nothrow_swappable_v<Types>)&&...);

    /// \brief Swaps two variant objects.
    constexpr auto swap(variant& rhs) noexcept(is_swap_noexcept) -> void
    {
        if (valueless_by_exception() && rhs.valueless_by_exception()) {
            return;
        }
        if (index() == rhs.index()) {
            detail::variant_swap_table<variant, Types...>[index()](*this, rhs);
        }
    }

    /// \todo Remove & replace with friendship for etl::get_if.
    [[nodiscard]] auto _impl() const noexcept { return &data_; } // NOLINT
    auto _impl() noexcept { return &data_; }                     // NOLINT

private:
    detail::variant_storage_for<Types...> data_;
    internal_size_t index_;
};

/// \brief Overloads the swap algorithm for variant. Effectively calls
/// lhs.swap(rhs).
///
/// \details This overload participates in overload resolution only if
/// is_move_constructible_v<T_i> and is_swappable_v<T_i> are both true for all
/// T_i in Types...
template <typename... Ts, TETL_REQUIRES_(detail::enable_variant_swap<Ts...>)>
constexpr auto swap(etl::variant<Ts...>& lhs,
    etl::variant<Ts...>& rhs) noexcept(noexcept(lhs.swap(rhs))) -> void
{
    lhs.swap(rhs);
}

/// \brief Equality operator for variants:
///     - If lhs.index() != rhs.index(), returns false;
///     - If lhs.valueless_by_exception(), returns true;
///     - Otherwise returns get<lhs.index()>(lhs) == get<lhs.index()>(rhs)
template <typename... Ts>
constexpr auto operator==(
    etl::variant<Ts...> const& lhs, etl::variant<Ts...> const& rhs) -> bool
{
    using var_t  = etl::variant<Ts...>;
    using cmp_t  = etl::equal_to<>;
    auto const i = lhs.index();
    if (i != rhs.index()) { return false; }
    return detail::variant_compare_table<cmp_t, var_t, Ts...>[i](lhs, rhs);
}

/// \brief Inequality operator for variants:
///     - If lhs.index() != rhs.index(), returns true;
///     - If lhs.valueless_by_exception(), returns false;
///     - Otherwise returns get<lhs.index()>(lhs) != get<lhs.index()>(rhs)
template <typename... Ts>
constexpr auto operator!=(
    etl::variant<Ts...> const& lhs, etl::variant<Ts...> const& rhs) -> bool
{
    return !(lhs == rhs);
}

/// \brief Less-than operator for variants:
///     - If rhs.valueless_by_exception(), returns false;
///     - If lhs.valueless_by_exception(), returns true;
///     - If lhs.index() < rhs.index(), returns true;
///     - If lhs.index() > rhs.index(), returns false;
///     - Otherwise returns get<lhs.index()>(v) < get<lhs.index()>(w)
template <typename... Ts>
constexpr auto operator<(
    etl::variant<Ts...> const& lhs, etl::variant<Ts...> const& rhs) -> bool
{
    // if (rhs.valueless_by_exception()) { return false; }
    // if (lhs.valueless_by_exception()) { return true; }

    auto const i = lhs.index();
    if (i < rhs.index()) { return true; }
    if (i > rhs.index()) { return false; }

    using var_t = etl::variant<Ts...>;
    using cmp_t = etl::less<>;
    return detail::variant_compare_table<cmp_t, var_t, Ts...>[i](lhs, rhs);
}

/// \brief Less-equal operator for variants:
///     - If lhs.valueless_by_exception(), returns true;
///     - If rhs.valueless_by_exception(), returns false;
///     - If lhs.index() < rhs.index(), returns true;
///     - If lhs.index() > rhs.index(), returns false;
///     - Otherwise returns get<lhs.index()>(v) <= get<lhs.index()>(w)
template <typename... Ts>
constexpr auto operator<=(
    etl::variant<Ts...> const& lhs, etl::variant<Ts...> const& rhs) -> bool
{
    // if (lhs.valueless_by_exception()) { return true; }
    // if (rhs.valueless_by_exception()) { return false; }

    auto const i = lhs.index();
    if (i < rhs.index()) { return true; }
    if (i > rhs.index()) { return false; }

    using var_t = etl::variant<Ts...>;
    using cmp_t = etl::less<>;
    return !detail::variant_compare_table<cmp_t, var_t, Ts...>[i](rhs, lhs);
}

/// \brief Greater-than operator for variants:
///     - If lhs.valueless_by_exception(), returns false;
///     - If rhs.valueless_by_exception(), returns true;
///     - If lhs.index() > rhs.index(), returns true;
///     - If lhs.index() < rhs.index(), returns false;
///     - Otherwise returns get<lhs.index()>(v) > get<lhs.index()>(w)
template <typename... Ts>
constexpr auto operator>(
    etl::variant<Ts...> const& lhs, etl::variant<Ts...> const& rhs) -> bool
{
    // if (lhs.valueless_by_exception()) { return false; }
    // if (rhs.valueless_by_exception()) { return true; }

    auto const i = lhs.index();
    if (i > rhs.index()) { return true; }
    if (i < rhs.index()) { return false; }

    using var_t = etl::variant<Ts...>;
    using cmp_t = etl::less<>;
    return detail::variant_compare_table<cmp_t, var_t, Ts...>[i](rhs, lhs);
}

/// \brief Greater-equal operator for variants:
///     - If lhs.valueless_by_exception(), returns false;
///     - If rhs.valueless_by_exception(), returns true;
///     - If lhs.index() > rhs.index(), returns true;
///     - If lhs.index() < rhs.index(), returns false;
///     - Otherwise returns get<lhs.index()>(v) >= get<lhs.index()>(w)
template <typename... Ts>
constexpr auto operator>=(
    etl::variant<Ts...> const& lhs, etl::variant<Ts...> const& rhs) -> bool
{
    // if (lhs.valueless_by_exception()) { return false; }
    // if (rhs.valueless_by_exception()) { return true; }

    auto const i = lhs.index();
    if (i > rhs.index()) { return true; }
    if (i < rhs.index()) { return false; }

    using var_t = etl::variant<Ts...>;
    using cmp_t = etl::less<>;
    return !detail::variant_compare_table<cmp_t, var_t, Ts...>[i](lhs, rhs);
}

/// \brief Checks if the variant v holds the alternative T. The call is
/// ill-formed if T does not appear exactly once in Types...
template <typename T, typename... Types>
constexpr auto holds_alternative(etl::variant<Types...> const& v) noexcept
    -> bool
{
    using index_t = decltype(v._impl()->get_index(etl::declval<T>()));
    return index_t::value == v.index();
}

/// \brief Index-based non-throwing accessor: If pv is not a null pointer and
/// pv->index() == I, returns a pointer to the value stored in the variant
/// pointed to by pv. Otherwise, returns a null pointer value. The call is
/// ill-formed if I is not a valid index in the variant.
///
/// \todo Implement
template <etl::size_t I, typename... Types>
constexpr auto get_if(etl::variant<Types...>* pv) noexcept
    -> etl::add_pointer_t<etl::variant_alternative_t<I, etl::variant<Types...>>>
{
    using alternative_t = etl::variant_alternative_t<I, etl::variant<Types...>>;
    return etl::get_if<alternative_t>(pv);
}

/// \brief Index-based non-throwing accessor: If pv is not a null pointer and
/// pv->index() == I, returns a pointer to the value stored in the variant
/// pointed to by pv. Otherwise, returns a null pointer value. The call is
/// ill-formed if I is not a valid index in the variant.
///
/// \todo Implement
template <etl::size_t I, typename... Types>
constexpr auto get_if(etl::variant<Types...> const* pv) noexcept
    -> etl::add_pointer_t<
        etl::variant_alternative_t<I, etl::variant<Types...>> const>
{
    using alternative_t = etl::variant_alternative_t<I, etl::variant<Types...>>;
    return etl::get_if<alternative_t>(pv);
}

/// \brief Type-based non-throwing accessor: The call is ill-formed if T is not
/// a unique element of Types....
template <typename T, typename... Types>
constexpr auto get_if(etl::variant<Types...>* v) noexcept
    -> etl::add_pointer_t<T>
{
    using idx  = decltype((*v)._impl()->get_index(etl::declval<T const>()));
    using ic_t = etl::integral_constant<etl::size_t, idx::value>;
    if (holds_alternative<T>(*v)) { return &(v->_impl()->get_value(ic_t {})); }
    return nullptr;
}

/// \brief Type-based non-throwing accessor: The call is ill-formed if T is not
/// a unique element of Types....
template <typename T, typename... Types>
constexpr auto get_if(etl::variant<Types...> const* v) noexcept
    -> etl::add_pointer_t<T const>
{
    using idx  = decltype((*v)._impl()->get_index(etl::declval<T>()));
    using ic_t = etl::integral_constant<etl::size_t, idx::value>;
    if (holds_alternative<T>(*v)) { return &(v->_impl()->get_value(ic_t {})); }
    return nullptr;
}

} // namespace etl

#endif // TETL_VARIANT_VARIANT_HPP