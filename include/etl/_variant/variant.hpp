// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_VARIANT_VARIANT_HPP
#define TETL_VARIANT_VARIANT_HPP

#include "etl/_array/array.hpp"
#include "etl/_container/smallest_size_t.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_exception/raise.hpp"
#include "etl/_functional/equal_to.hpp"
#include "etl/_functional/greater.hpp"
#include "etl/_functional/greater_equal.hpp"
#include "etl/_functional/less.hpp"
#include "etl/_functional/less_equal.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_new/operator.hpp"
#include "etl/_type_traits/add_pointer.hpp"
#include "etl/_type_traits/aligned_storage.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/integral_constant.hpp"
#include "etl/_type_traits/is_default_constructible.hpp"
#include "etl/_type_traits/is_nothrow_default_constructible.hpp"
#include "etl/_type_traits/is_nothrow_move_constructible.hpp"
#include "etl/_type_traits/is_nothrow_swappable.hpp"
#include "etl/_type_traits/is_same.hpp"
#include "etl/_type_traits/type_pack_element.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/in_place_index.hpp"
#include "etl/_utility/in_place_type.hpp"
#include "etl/_utility/index_sequence.hpp"
#include "etl/_utility/move.hpp"
#include "etl/_utility/swap.hpp"
#include "etl/_variant/bad_variant_access.hpp"
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

template <typename Variant, size_t Index>
constexpr auto variant_swap_func(Variant& lhs, Variant& rhs) -> void
{
    using etl::swap;
    swap(*get_if<Index>(&lhs), *get_if<Index>(&rhs));
}

template <typename Variant, size_t... Indices>
constexpr auto make_variant_swap_table(index_sequence<Indices...> /*is*/)
{
    return array { &variant_swap_func<Variant, Indices>... };
}

template <typename Variant, typename... Ts>
inline constexpr auto variant_swap_table = make_variant_swap_table<Variant>(index_sequence_for<Ts...> {});

// compare
template <typename Variant>
using variant_cmp_func_t = bool (*)(Variant const&, Variant const&);

template <typename Op, typename Variant, size_t Index>
constexpr auto variant_compare_func(Variant const& l, Variant const& r) -> bool
{
    return Op {}(*get_if<Index>(&l), *get_if<Index>(&r));
}

template <typename Op, typename Variant, size_t... Indices>
constexpr auto make_variant_compare_table(index_sequence<Indices...> /*is*/)
{
    return array { &variant_compare_func<Op, Variant, Indices>... };
}

template <typename Op, typename Variant, typename... Ts>
inline constexpr auto variant_compare_table = make_variant_compare_table<Op, Variant>(index_sequence_for<Ts...> {});

template <size_t Index, typename...>
struct variant_storage;

template <size_t Index, typename Head>
struct variant_storage<Index, Head> {
    using storage_t = aligned_storage_t<sizeof(Head), alignof(Head)>;
    storage_t data;

    template <typename T>
    constexpr auto construct(T&& head, size_t& index) -> void
    {
        new (&data) Head(forward<T>(head));
        index = 0;
    }

    template <typename T, typename... Args>
    constexpr auto construct(in_place_type_t<T> /*tag*/, size_t& index, Args&&... args) -> void
    {
        new (&data) Head(forward<Args>(args)...);
        index = 0;
    }

    constexpr auto destruct(size_t /*unused*/) -> void { static_cast<Head*>(static_cast<void*>(&data))->~Head(); }

    [[nodiscard]] constexpr auto get_index(Head const& /*head*/) const -> integral_constant<size_t, Index>
    {
        return {};
    }

    [[nodiscard]] constexpr auto get_value(integral_constant<size_t, Index> /*ic*/) & -> Head& { return *to_ptr(); }

    [[nodiscard]] constexpr auto get_value(integral_constant<size_t, Index> /*ic*/) const& -> Head const&
    {
        return *to_ptr();
    }

    [[nodiscard]] constexpr auto get_value(integral_constant<size_t, Index> /*ic*/) && -> Head&&
    {
        return move(*to_ptr());
    }

    [[nodiscard]] constexpr auto get_value(integral_constant<size_t, Index> /*ic*/) const&& -> Head const&&
    {
        return move(*to_ptr());
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
        new (&data) Head(move(head));
        index = 0;
    }

    template <typename... Args>
    constexpr auto construct(in_place_type_t<Head> /*tag*/, size_t& index, Args&&... args) -> void
    {
        new (&data) Head(forward<Args>(args)...);
        index = 0;
    }

    template <typename T>
    constexpr auto construct(T&& t, size_t& index) -> void
    {
        tail.construct(forward<T>(t), index);
        ++index;
    }

    template <typename T, typename... Args>
    constexpr auto construct(in_place_type_t<T> tag, size_t& index, Args&&... args) -> void
    {
        tail.construct(tag, index, forward<Args>(args)...);
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

    [[nodiscard]] constexpr auto get_index(Head const& /*head*/) const -> integral_constant<size_t, Index>
    {
        return {};
    }

    template <typename T>
    [[nodiscard]] constexpr auto get_index(T const& t) const
    {
        return tail.get_index(t);
    }

    [[nodiscard]] constexpr auto get_value(integral_constant<size_t, Index> /*ic*/) & -> Head& { return *to_ptr(); }

    [[nodiscard]] constexpr auto get_value(integral_constant<size_t, Index> /*ic*/) const& -> Head const&
    {
        return *to_ptr();
    }

    [[nodiscard]] constexpr auto get_value(integral_constant<size_t, Index> /*ic*/) && -> Head&&
    {
        return move(*to_ptr());
    }

    [[nodiscard]] constexpr auto get_value(integral_constant<size_t, Index> /*ic*/) const&& -> Head const&&
    {
        return move(*to_ptr());
    }

    template <size_t N>
    [[nodiscard]] constexpr auto get_value(integral_constant<size_t, N> ic) & -> auto&
    {
        return tail.get_value(ic);
    }

    template <size_t N>
    [[nodiscard]] constexpr auto get_value(integral_constant<size_t, N> ic) const& -> auto const&
    {
        return tail.get_value(ic);
    }

    template <size_t N>
    [[nodiscard]] constexpr auto get_value(integral_constant<size_t, N> ic) && -> auto&&
    {
        return move(tail).get_value(ic);
    }

    template <size_t N>
    [[nodiscard]] constexpr auto get_value(integral_constant<size_t, N> ic) const&& -> auto const&&
    {
        return move(tail).get_value(ic);
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
inline constexpr auto enable_variant_swap = ((is_move_constructible_v<Ts> && is_swappable_v<Ts>)&&...);

} // namespace detail

/// \brief This is a special value equal to the largest value representable by
/// the type size_t, used as the return value of index() when
/// valueless_by_exception() is true.
inline constexpr auto variant_npos = numeric_limits<size_t>::max();

/// \brief The class template variant represents a type-safe union. An
/// instance of variant at any given time either holds a value of one of
/// its alternative types.
template <typename... Types>
struct variant {
private:
    using internal_size_t = smallest_size_t<sizeof...(Types)>;
    using first_type      = type_pack_element_t<0, Types...>;

public:
    constexpr variant() noexcept(noexcept(is_nothrow_default_constructible_v<first_type>))
        requires(is_default_constructible_v<first_type>)
    {
        auto tmpIndex = size_t { _index };
        _data.construct(in_place_type<first_type>, tmpIndex);
        _index = static_cast<internal_size_t>(tmpIndex);
    }

    /// \brief (4) Converting constructor.
    /// \details Constructs a variant holding the alternative type T.
    ///
    /// https://en.cppreference.com/w/cpp/utility/variant/variant
    template <typename T>
    explicit variant(T&& t)
    {
        auto tmpIndex = size_t { _index };
        _data.construct(forward<T>(t), tmpIndex);
        _index = static_cast<internal_size_t>(tmpIndex);
    }

    /// \brief (5) Constructs a variant with the specified alternative T and
    /// initializes the contained value with the arguments
    /// forward<Args>(args)....
    ///
    /// \details This overload participates in overload resolution only if there
    /// is exactly one occurrence of T in Types... and
    /// is_constructible_v<T, Args...> is true.
    ///
    /// https://en.cppreference.com/w/cpp/utility/variant/variant
    ///
    /// \bug Improve sfinae (single unique type in variant)
    template <typename T, typename... Args>
        requires(is_constructible_v<T, Args...>)
    constexpr explicit variant(in_place_type_t<T> tag, Args&&... args)
    {
        auto tmpIndex = size_t { _index };
        _data.construct(tag, tmpIndex, forward<Args>(args)...);
        _index = static_cast<internal_size_t>(tmpIndex);
    }

    /// \brief (7) Constructs a variant with the alternative T_i specified by
    /// the index I and initializes the contained value with the arguments
    /// forward<Args>(args)...
    ///
    /// \details This overload participates in overload resolution only if I <
    /// sizeof...(Types) and is_constructible_v<T_i, Args...> is true.
    ///
    /// https://en.cppreference.com/w/cpp/utility/variant/variant
    template <size_t I, typename... Args>
        requires(I < sizeof...(Types)) && (is_constructible_v<variant_alternative_t<I, variant>, Args...>)
    constexpr explicit variant(in_place_index_t<I> /*tag*/, Args&&... args)
        : variant(in_place_type<variant_alternative_t<I, variant>>, forward<Args>(args)...)
    {
    }

    /// \brief If valueless_by_exception is true, does nothing. Otherwise,
    /// destroys the currently contained value.
    /// \todo This destructor is trivial if
    /// is_trivially_destructible_v<T_i> is true for all T_i in Types...
    ~variant()
    {
        if (!valueless_by_exception()) { _data.destruct(_index); }
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
            _data = rhs._data;
            return *this;
        }

        return *this;
    }

    /// \brief Returns the zero-based index of the alternative that is currently
    /// held by the variant. If the variant is valueless_by_exception, returns
    /// variant_npos.
    [[nodiscard]] constexpr auto index() const noexcept -> size_t
    {
        return valueless_by_exception() ? variant_npos : _index;
    }

    /// \brief Returns false if and only if the variant holds a value. Currently
    /// always returns false, since there is no default constructor.
    [[nodiscard]] constexpr auto valueless_by_exception() const noexcept -> bool { return false; }

    /// \brief Swaps two variant objects.
    constexpr auto swap(variant& rhs) noexcept(
        ((is_nothrow_move_constructible_v<Types> && is_nothrow_swappable_v<Types>)&&...)) -> void
    {
        if (index() == rhs.index()) { detail::variant_swap_table<variant, Types...>[index()](*this, rhs); }
    }

    /// \todo Remove & replace with friendship for get_if.
    [[nodiscard]] auto _impl() const noexcept { return &_data; } // NOLINT
    auto _impl() noexcept { return &_data; }                     // NOLINT

private:
    detail::variant_storage_for<Types...> _data;
    internal_size_t _index { 0 };
};

/// \brief Overloads the swap algorithm for variant. Effectively calls
/// lhs.swap(rhs).
///
/// \details This overload participates in overload resolution only if
/// is_move_constructible_v<T_i> and is_swappable_v<T_i> are both true for all
/// T_i in Types...
template <typename... Ts>
    requires(detail::enable_variant_swap<Ts...>)
constexpr auto swap(variant<Ts...>& lhs, variant<Ts...>& rhs) noexcept(noexcept(lhs.swap(rhs))) -> void
{
    lhs.swap(rhs);
}

/// \brief Equality operator for variants:
///     - If lhs.index() != rhs.index(), returns false;
///     - If lhs.valueless_by_exception(), returns true;
///     - Otherwise returns get<lhs.index()>(lhs) == get<lhs.index()>(rhs)
template <typename... Ts>
constexpr auto operator==(variant<Ts...> const& lhs, variant<Ts...> const& rhs) -> bool
{
    auto const i = lhs.index();
    if (i != rhs.index()) { return false; }
    return detail::variant_compare_table<equal_to<>, variant<Ts...>, Ts...>[i](lhs, rhs);
}

/// \brief Inequality operator for variants:
///     - If lhs.index() != rhs.index(), returns true;
///     - If lhs.valueless_by_exception(), returns false;
///     - Otherwise returns get<lhs.index()>(lhs) != get<lhs.index()>(rhs)
template <typename... Ts>
constexpr auto operator!=(variant<Ts...> const& lhs, variant<Ts...> const& rhs) -> bool
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
constexpr auto operator<(variant<Ts...> const& lhs, variant<Ts...> const& rhs) -> bool
{
    // if (rhs.valueless_by_exception()) { return false; }
    // if (lhs.valueless_by_exception()) { return true; }

    auto const i = lhs.index();
    if (i < rhs.index()) { return true; }
    if (i > rhs.index()) { return false; }

    using var_t = variant<Ts...>;
    using cmp_t = less<>;
    return detail::variant_compare_table<cmp_t, var_t, Ts...>[i](lhs, rhs);
}

/// \brief Less-equal operator for variants:
///     - If lhs.valueless_by_exception(), returns true;
///     - If rhs.valueless_by_exception(), returns false;
///     - If lhs.index() < rhs.index(), returns true;
///     - If lhs.index() > rhs.index(), returns false;
///     - Otherwise returns get<lhs.index()>(v) <= get<lhs.index()>(w)
template <typename... Ts>
constexpr auto operator<=(variant<Ts...> const& lhs, variant<Ts...> const& rhs) -> bool
{
    // if (lhs.valueless_by_exception()) { return true; }
    // if (rhs.valueless_by_exception()) { return false; }

    auto const i = lhs.index();
    if (i < rhs.index()) { return true; }
    if (i > rhs.index()) { return false; }

    using var_t = variant<Ts...>;
    using cmp_t = less<>;
    return !detail::variant_compare_table<cmp_t, var_t, Ts...>[i](rhs, lhs);
}

/// \brief Greater-than operator for variants:
///     - If lhs.valueless_by_exception(), returns false;
///     - If rhs.valueless_by_exception(), returns true;
///     - If lhs.index() > rhs.index(), returns true;
///     - If lhs.index() < rhs.index(), returns false;
///     - Otherwise returns get<lhs.index()>(v) > get<lhs.index()>(w)
template <typename... Ts>
constexpr auto operator>(variant<Ts...> const& lhs, variant<Ts...> const& rhs) -> bool
{
    // if (lhs.valueless_by_exception()) { return false; }
    // if (rhs.valueless_by_exception()) { return true; }

    auto const i = lhs.index();
    if (i > rhs.index()) { return true; }
    if (i < rhs.index()) { return false; }

    using var_t = variant<Ts...>;
    using cmp_t = less<>;
    return detail::variant_compare_table<cmp_t, var_t, Ts...>[i](rhs, lhs);
}

/// \brief Greater-equal operator for variants:
///     - If lhs.valueless_by_exception(), returns false;
///     - If rhs.valueless_by_exception(), returns true;
///     - If lhs.index() > rhs.index(), returns true;
///     - If lhs.index() < rhs.index(), returns false;
///     - Otherwise returns get<lhs.index()>(v) >= get<lhs.index()>(w)
template <typename... Ts>
constexpr auto operator>=(variant<Ts...> const& lhs, variant<Ts...> const& rhs) -> bool
{
    // if (lhs.valueless_by_exception()) { return false; }
    // if (rhs.valueless_by_exception()) { return true; }

    auto const i = lhs.index();
    if (i > rhs.index()) { return true; }
    if (i < rhs.index()) { return false; }

    using var_t = variant<Ts...>;
    using cmp_t = less<>;
    return !detail::variant_compare_table<cmp_t, var_t, Ts...>[i](lhs, rhs);
}

/// \brief Checks if the variant v holds the alternative T. The call is
/// ill-formed if T does not appear exactly once in Types...
template <typename T, typename... Types>
constexpr auto holds_alternative(variant<Types...> const& v) noexcept -> bool
{
    using index_t = decltype(v._impl()->get_index(declval<T>()));
    return index_t::value == v.index();
}

/// \brief Index-based non-throwing accessor: If pv is not a null pointer and
/// pv->index() == I, returns a pointer to the value stored in the variant
/// pointed to by pv. Otherwise, returns a null pointer value. The call is
/// ill-formed if I is not a valid index in the variant.
template <size_t I, typename... Types>
constexpr auto get_if(variant<Types...>* pv) noexcept -> add_pointer_t<variant_alternative_t<I, variant<Types...>>>
{
    using alternative_t = variant_alternative_t<I, variant<Types...>>;
    return get_if<alternative_t>(pv);
}

/// \brief Index-based non-throwing accessor: If pv is not a null pointer and
/// pv->index() == I, returns a pointer to the value stored in the variant
/// pointed to by pv. Otherwise, returns a null pointer value. The call is
/// ill-formed if I is not a valid index in the variant.
template <size_t I, typename... Types>
constexpr auto get_if(variant<Types...> const* pv) noexcept
    -> add_pointer_t<variant_alternative_t<I, variant<Types...>> const>
{
    using alternative_t = variant_alternative_t<I, variant<Types...>>;
    return get_if<alternative_t>(pv);
}

/// \brief Type-based non-throwing accessor: The call is ill-formed if T is not
/// a unique element of Types....
template <typename T, typename... Types>
constexpr auto get_if(variant<Types...>* v) noexcept -> add_pointer_t<T>
{
    using idx  = decltype((*v)._impl()->get_index(declval<T>()));
    using ic_t = integral_constant<size_t, idx::value>;
    if (holds_alternative<T>(*v)) { return &(v->_impl()->get_value(ic_t {})); }
    return nullptr;
}

/// \brief Type-based non-throwing accessor: The call is ill-formed if T is not
/// a unique element of Types....
template <typename T, typename... Types>
constexpr auto get_if(variant<Types...> const* v) noexcept -> add_pointer_t<T const>
{
    using idx  = decltype((*v)._impl()->get_index(declval<T const>()));
    using ic_t = integral_constant<size_t, idx::value>;
    if (holds_alternative<T>(*v)) { return &(v->_impl()->get_value(ic_t {})); }
    return nullptr;
}

/// \brief Index-based value accessor
///
/// \details If v.index() == I, returns a reference to the value stored in v.
/// Otherwise, raises a bad_variant_access. The call is ill-formed if I is
/// not a valid index in the variant.
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <size_t I, typename... Types>
[[nodiscard]] constexpr auto get(variant<Types...>& v) -> variant_alternative_t<I, variant<Types...>>&
{
    static_assert(I < sizeof...(Types));
    if (v.index() == I) { return *get_if<I>(&v); }
    raise<bad_variant_access>("");
}

/// \brief Index-based value accessor
///
/// \details If v.index() == I, returns a reference to the value stored in v.
/// Otherwise, raises a bad_variant_access. The call is ill-formed if I is
/// not a valid index in the variant.
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <size_t I, typename... Types>
[[nodiscard]] constexpr auto get(variant<Types...>&& v) -> variant_alternative_t<I, variant<Types...>>&&
{
    static_assert(I < sizeof...(Types));
    if (v.index() == I) { return move(*get_if<I>(&v)); }
    raise<bad_variant_access>("");
}

/// \brief Index-based value accessor
///
/// \details If v.index() == I, returns a reference to the value stored in v.
/// Otherwise, raises a bad_variant_access. The call is ill-formed if I is
/// not a valid index in the variant.
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <size_t I, typename... Types>
[[nodiscard]] constexpr auto get(variant<Types...> const& v) -> variant_alternative_t<I, variant<Types...>> const&
{
    static_assert(I < sizeof...(Types));
    if (v.index() == I) { return *get_if<I>(&v); }
    raise<bad_variant_access>("");
}

/// \brief Index-based value accessor
///
/// \details If v.index() == I, returns a reference to the value stored in v.
/// Otherwise, raises a bad_variant_access. The call is ill-formed if I is
/// not a valid index in the variant.
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <size_t I, typename... Types>
[[nodiscard]] constexpr auto get(variant<Types...> const&& v) -> variant_alternative_t<I, variant<Types...>> const&&
{
    static_assert(I < sizeof...(Types));
    if (v.index() == I) { return move(*get_if<I>(&v)); }
    raise<bad_variant_access>("");
}

/// \brief Type-based value accessor
///
/// \details If v holds the alternative T, returns a reference to the value
/// stored in v. Otherwise, throws bad_variant_access. The call is
/// ill-formed if T is not a unique element of Types....
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <typename T, typename... Types>
[[nodiscard]] constexpr auto get(variant<Types...>& v) -> T&
{
    if (holds_alternative<T>(v)) { return *get_if<T>(&v); }
    raise<bad_variant_access>("");
}

/// \brief Type-based value accessor
///
/// \details If v holds the alternative T, returns a reference to the value
/// stored in v. Otherwise, throws bad_variant_access. The call is
/// ill-formed if T is not a unique element of Types....
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <typename T, typename... Types>
[[nodiscard]] constexpr auto get(variant<Types...>&& v) -> T&&
{
    if (holds_alternative<T>(v)) { return move(*get_if<T>(&v)); }
    raise<bad_variant_access>("");
}

/// \brief Type-based value accessor
///
/// \details If v holds the alternative T, returns a reference to the value
/// stored in v. Otherwise, throws bad_variant_access. The call is
/// ill-formed if T is not a unique element of Types....
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <typename T, typename... Types>
[[nodiscard]] constexpr auto get(variant<Types...> const& v) -> T const&
{
    if (holds_alternative<T>(v)) { return *get_if<T>(&v); }
    raise<bad_variant_access>("");
}

/// \brief Type-based value accessor
///
/// \details If v holds the alternative T, returns a reference to the value
/// stored in v. Otherwise, throws bad_variant_access. The call is
/// ill-formed if T is not a unique element of Types....
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <typename T, typename... Types>
[[nodiscard]] constexpr auto get(variant<Types...> const&& v) -> T const&&
{
    if (holds_alternative<T>(v)) { return move(*get_if<T>(&v)); }
    raise<bad_variant_access>("");
}

} // namespace etl

#endif // TETL_VARIANT_VARIANT_HPP
