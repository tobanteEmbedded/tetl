// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_VARIANT_VARIANT_HPP
#define TETL_VARIANT_VARIANT_HPP

#include <etl/_array/array.hpp>
#include <etl/_container/smallest_size_t.hpp>
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
#include <etl/_type_traits/type_pack_element.hpp>
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
#include <etl/_warning/ignore_unused.hpp>

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
    return array{&variant_swap_func<Variant, Indices>...};
}

template <typename Variant, typename... Ts>
inline constexpr auto variant_swap_table = make_variant_swap_table<Variant>(index_sequence_for<Ts...>{});

// compare
template <typename Variant>
using variant_cmp_func_t = bool (*)(Variant const&, Variant const&);

template <typename Op, typename Variant, size_t Index>
constexpr auto variant_compare_func(Variant const& l, Variant const& r) -> bool
{
    return Op{}(*get_if<Index>(&l), *get_if<Index>(&r));
}

template <typename Op, typename Variant, size_t... Indices>
constexpr auto make_variant_compare_table(index_sequence<Indices...> /*is*/)
{
    return array{&variant_compare_func<Op, Variant, Indices>...};
}

template <typename Op, typename Variant, typename... Ts>
inline constexpr auto variant_compare_table = make_variant_compare_table<Op, Variant>(index_sequence_for<Ts...>{});

template <size_t Index, typename...>
struct variant_storage;

template <size_t Index, typename Head>
struct variant_storage<Index, Head> {
    using storage_t = aligned_storage_t<sizeof(Head), alignof(Head)>;
    storage_t data;

    template <typename T>
    constexpr auto construct(T&& head, size_t& index) -> void
    {
        new (&data) Head(TETL_FORWARD(head));
        index = 0;
    }

    template <typename T, typename... Args>
    constexpr auto construct(in_place_type_t<T> /*tag*/, size_t& index, Args&&... args) -> void
    {
        new (&data) Head(TETL_FORWARD(args)...);
        index = 0;
    }

    constexpr auto destruct(size_t /*unused*/) -> void { static_cast<Head*>(static_cast<void*>(&data))->~Head(); }

    [[nodiscard]] constexpr auto get_index(Head const& /*head*/) const -> index_constant<Index> { return {}; }

    [[nodiscard]] constexpr auto get_value(index_constant<Index> /*ic*/) & -> Head& { return *to_ptr(); }

    [[nodiscard]] constexpr auto get_value(index_constant<Index> /*ic*/) const& -> Head const& { return *to_ptr(); }

    [[nodiscard]] constexpr auto get_value(index_constant<Index> /*ic*/) && -> Head&& { return TETL_MOVE(*to_ptr()); }

    [[nodiscard]] constexpr auto get_value(index_constant<Index> /*ic*/) const&& -> Head const&&
    {
        return TETL_MOVE(*to_ptr());
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
        new (&data) Head(TETL_MOVE(head));
        index = 0;
    }

    template <typename... Args>
    constexpr auto construct(in_place_type_t<Head> /*tag*/, size_t& index, Args&&... args) -> void
    {
        new (&data) Head(TETL_FORWARD(args)...);
        index = 0;
    }

    template <typename T>
    constexpr auto construct(T&& t, size_t& index) -> void
    {
        tail.construct(TETL_FORWARD(t), index);
        ++index;
    }

    template <typename T, typename... Args>
    constexpr auto construct(in_place_type_t<T> tag, size_t& index, Args&&... args) -> void
    {
        tail.construct(tag, index, TETL_FORWARD(args)...);
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

    [[nodiscard]] constexpr auto get_index(Head const& /*head*/) const -> index_constant<Index> { return {}; }

    template <typename T>
    [[nodiscard]] constexpr auto get_index(T const& t) const
    {
        return tail.get_index(t);
    }

    [[nodiscard]] constexpr auto get_value(index_constant<Index> /*ic*/) & -> Head& { return *to_ptr(); }

    [[nodiscard]] constexpr auto get_value(index_constant<Index> /*ic*/) const& -> Head const& { return *to_ptr(); }

    [[nodiscard]] constexpr auto get_value(index_constant<Index> /*ic*/) && -> Head&& { return TETL_MOVE(*to_ptr()); }

    [[nodiscard]] constexpr auto get_value(index_constant<Index> /*ic*/) const&& -> Head const&&
    {
        return TETL_MOVE(*to_ptr());
    }

    template <size_t N>
    [[nodiscard]] constexpr auto get_value(index_constant<N> ic) & -> auto&
    {
        return tail.get_value(ic);
    }

    template <size_t N>
    [[nodiscard]] constexpr auto get_value(index_constant<N> ic) const& -> auto const&
    {
        return tail.get_value(ic);
    }

    template <size_t N>
    [[nodiscard]] constexpr auto get_value(index_constant<N> ic) && -> auto&&
    {
        return TETL_MOVE(tail).get_value(ic);
    }

    template <size_t N>
    [[nodiscard]] constexpr auto get_value(index_constant<N> ic) const&& -> auto const&&
    {
        return TETL_MOVE(tail).get_value(ic);
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

/// \brief This is a special value equal to the largest value representable by the
/// type size_t, used as the return value of index() when valueless_by_exception() is true.
inline constexpr auto variant_npos = etl::numeric_limits<etl::size_t>::max();

/// \brief The class template variant represents a type-safe union. An
/// instance of variant at any given time either holds a value of one of
/// its alternative types.
template <typename... Ts>
struct variant {
private:
    using internal_size_t = etl::smallest_size_t<sizeof...(Ts)>;
    using first_type      = etl::type_pack_element_t<0, Ts...>;

public:
    constexpr variant() noexcept(noexcept(etl::is_nothrow_default_constructible_v<first_type>))
        requires(etl::is_default_constructible_v<first_type>)
    {
        auto tmpIndex = etl::size_t{_index};
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
        auto tmpIndex = size_t{_index};
        _data.construct(TETL_FORWARD(t), tmpIndex);
        _index = static_cast<internal_size_t>(tmpIndex);
    }

    /// \brief (5) Constructs a variant with the specified alternative T and
    /// initializes the contained value with the arguments
    /// TETL_FORWARD(args)....
    ///
    /// \details This overload participates in overload resolution only if there
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
        _data.construct(tag, tmpIndex, TETL_FORWARD(args)...);
        _index = static_cast<internal_size_t>(tmpIndex);
    }

    /// \brief (7) Constructs a variant with the alternative T_i specified by
    /// the index I and initializes the contained value with the arguments
    /// TETL_FORWARD(args)...
    ///
    /// \details This overload participates in overload resolution only if I <
    /// sizeof...(Ts) and is_constructible_v<T_i, Args...> is true.
    ///
    /// https://en.cppreference.com/w/cpp/utility/variant/variant
    template <etl::size_t I, typename... Args>
        requires(I < sizeof...(Ts) and etl::is_constructible_v<etl::variant_alternative_t<I, variant>, Args...>)
    constexpr explicit variant(etl::in_place_index_t<I> /*tag*/, Args&&... args)
        : variant(in_place_type<etl::variant_alternative_t<I, variant>>, TETL_FORWARD(args)...)
    {
    }

    /// \brief If valueless_by_exception is true, does nothing. Otherwise,
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
                 and (0 + ... + etl::is_same_v<etl::remove_cvref_t<T>, Ts>) == 1)
    constexpr auto operator=(T&& rhs) -> variant&
    {
        auto v = variant(etl::in_place_type<T>, TETL_FORWARD(rhs));
        v.swap(*this);
        return *this;
    }

    template <typename T, typename... Args>
    constexpr auto emplace(Args&&... args) -> T&;

    template <etl::size_t I, typename... Args>
    constexpr auto emplace(Args&&... args) -> etl::variant_alternative_t<I, variant>&;

    /// \brief Returns the zero-based index of the alternative that is currently
    /// held by the variant. If the variant is valueless_by_exception, returns
    /// variant_npos.
    [[nodiscard]] constexpr auto index() const noexcept -> etl::size_t
    {
        return valueless_by_exception() ? variant_npos : _index;
    }

    /// \brief Returns false if and only if the variant holds a value. Currently
    /// always returns false, since there is no default constructor.
    [[nodiscard]] constexpr auto valueless_by_exception() const noexcept -> bool { return false; }

    /// \brief Swaps two variant objects.
    constexpr auto swap(variant& rhs
    ) noexcept(((is_nothrow_move_constructible_v<Ts> && is_nothrow_swappable_v<Ts>) && ...)) -> void
    {
        if (index() == rhs.index()) {
            return detail::variant_swap_table<variant, Ts...>[index()](*this, rhs);
        }
        etl::swap(_data, rhs._data);
        etl::swap(_index, rhs._index);
    }

    /// \todo Remove & replace with friendship for get_if.
    [[nodiscard]] auto impl() const noexcept { return &_data; } // NOLINT

    auto impl() noexcept { return &_data; } // NOLINT

private:
    etl::detail::variant_storage_for<Ts...> _data;
    internal_size_t _index{0};
};

/// \brief Overloads the swap algorithm for variant. Effectively calls
/// lhs.swap(rhs).
///
/// \details This overload participates in overload resolution only if
/// is_move_constructible_v<T_i> and is_swappable_v<T_i> are both true for all
/// T_i in Ts...
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
    if (i != rhs.index()) {
        return false;
    }
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
    if (i < rhs.index()) {
        return true;
    }
    if (i > rhs.index()) {
        return false;
    }

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
    if (i < rhs.index()) {
        return true;
    }
    if (i > rhs.index()) {
        return false;
    }

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
    if (i > rhs.index()) {
        return true;
    }
    if (i < rhs.index()) {
        return false;
    }

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
    if (i > rhs.index()) {
        return true;
    }
    if (i < rhs.index()) {
        return false;
    }

    using var_t = variant<Ts...>;
    using cmp_t = less<>;
    return !detail::variant_compare_table<cmp_t, var_t, Ts...>[i](lhs, rhs);
}

/// \brief Checks if the variant v holds the alternative T. The call is
/// ill-formed if T does not appear exactly once in Ts...
template <typename T, typename... Ts>
constexpr auto holds_alternative(variant<Ts...> const& v) noexcept -> bool
{
    using index_t = decltype(v.impl()->get_index(declval<T>()));
    return index_t::value == v.index();
}

/// \brief Returns a reference to the object stored in the variant.
/// \pre v.index() == I
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant<Ts...>& v) -> variant_alternative_t<I, variant<Ts...>>&
{
    return v.impl()->get_value(index_c<I>);
}

/// \brief Returns a reference to the object stored in the variant.
/// \pre v.index() == I
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant<Ts...> const& v) -> variant_alternative_t<I, variant<Ts...>> const&
{
    return v.impl()->get_value(index_c<I>);
}

/// \brief Returns a reference to the object stored in the variant.
/// \pre v.index() == I
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant<Ts...>&& v) -> variant_alternative_t<I, variant<Ts...>>&&
{
    return TETL_MOVE(v.impl()->get_value(index_c<I>));
}

/// \brief Returns a reference to the object stored in the variant.
/// \pre v.index() == I
template <etl::size_t I, typename... Ts>
constexpr auto unchecked_get(variant<Ts...> const&& v) -> variant_alternative_t<I, variant<Ts...>> const&&
{
    return TETL_MOVE(v.impl()->get_value(index_c<I>));
}

/// \brief Index-based non-throwing accessor: If pv is not a null pointer and
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

/// \brief Index-based non-throwing accessor: If pv is not a null pointer and
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

/// \brief Type-based non-throwing accessor: The call is ill-formed if T is not
/// a unique element of Ts....
template <typename T, typename... Ts>
constexpr auto get_if(variant<Ts...>* pv) noexcept -> add_pointer_t<T>
{
    using index = decltype(pv->impl()->get_index(etl::declval<T>()));
    return etl::get_if<index::value>(pv);
}

/// \brief Type-based non-throwing accessor: The call is ill-formed if T is not
/// a unique element of Ts....
template <typename T, typename... Ts>
constexpr auto get_if(variant<Ts...> const* pv) noexcept -> add_pointer_t<T const>
{
    using index = decltype(pv->impl()->get_index(etl::declval<T>()));
    return etl::get_if<index::value>(pv);
}

/// \brief Index-based value accessor
///
/// \details If v.index() == I, returns a reference to the value stored in v.
/// Otherwise, raises a bad_variant_access. The call is ill-formed if I is
/// not a valid index in the variant.
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(variant<Ts...>& v) -> variant_alternative_t<I, variant<Ts...>>&
{
    static_assert(I < sizeof...(Ts));
    if (v.index() == I) {
        return etl::unchecked_get<I>(v);
    }
    etl::raise<etl::bad_variant_access>("");
}

/// \brief Index-based value accessor
///
/// \details If v.index() == I, returns a reference to the value stored in v.
/// Otherwise, raises a bad_variant_access. The call is ill-formed if I is
/// not a valid index in the variant.
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(variant<Ts...>&& v) -> variant_alternative_t<I, variant<Ts...>>&&
{
    static_assert(I < sizeof...(Ts));
    if (v.index() == I) {
        return etl::unchecked_get<I>(TETL_MOVE(v));
    }
    etl::raise<etl::bad_variant_access>("");
}

/// \brief Index-based value accessor
///
/// \details If v.index() == I, returns a reference to the value stored in v.
/// Otherwise, raises a bad_variant_access. The call is ill-formed if I is
/// not a valid index in the variant.
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(variant<Ts...> const& v) -> variant_alternative_t<I, variant<Ts...>> const&
{
    static_assert(I < sizeof...(Ts));
    if (v.index() == I) {
        return etl::unchecked_get<I>(v);
    }
    etl::raise<etl::bad_variant_access>("");
}

/// \brief Index-based value accessor
///
/// \details If v.index() == I, returns a reference to the value stored in v.
/// Otherwise, raises a bad_variant_access. The call is ill-formed if I is
/// not a valid index in the variant.
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <size_t I, typename... Ts>
[[nodiscard]] constexpr auto get(variant<Ts...> const&& v) -> variant_alternative_t<I, variant<Ts...>> const&&
{
    static_assert(I < sizeof...(Ts));
    if (v.index() == I) {
        return etl::unchecked_get<I>(TETL_MOVE(v));
    }
    etl::raise<etl::bad_variant_access>("");
}

/// \brief Type-based value accessor
///
/// \details If v holds the alternative T, returns a reference to the value
/// stored in v. Otherwise, throws bad_variant_access. The call is
/// ill-formed if T is not a unique element of Ts....
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <typename T, typename... Ts>
[[nodiscard]] constexpr auto get(variant<Ts...>& v) -> T&
{
    if (holds_alternative<T>(v)) {
        return *get_if<T>(&v);
    }
    etl::raise<etl::bad_variant_access>("");
}

/// \brief Type-based value accessor
///
/// \details If v holds the alternative T, returns a reference to the value
/// stored in v. Otherwise, throws bad_variant_access. The call is
/// ill-formed if T is not a unique element of Ts....
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <typename T, typename... Ts>
[[nodiscard]] constexpr auto get(variant<Ts...>&& v) -> T&&
{
    if (holds_alternative<T>(v)) {
        return TETL_MOVE(*get_if<T>(&v));
    }
    etl::raise<etl::bad_variant_access>("");
}

/// \brief Type-based value accessor
///
/// \details If v holds the alternative T, returns a reference to the value
/// stored in v. Otherwise, throws bad_variant_access. The call is
/// ill-formed if T is not a unique element of Ts....
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <typename T, typename... Ts>
[[nodiscard]] constexpr auto get(variant<Ts...> const& v) -> T const&
{
    if (holds_alternative<T>(v)) {
        return *get_if<T>(&v);
    }
    etl::raise<etl::bad_variant_access>("");
}

/// \brief Type-based value accessor
///
/// \details If v holds the alternative T, returns a reference to the value
/// stored in v. Otherwise, throws bad_variant_access. The call is
/// ill-formed if T is not a unique element of Ts....
///
/// https://en.cppreference.com/w/cpp/utility/variant/get
template <typename T, typename... Ts>
[[nodiscard]] constexpr auto get(variant<Ts...> const&& v) -> T const&&
{
    if (holds_alternative<T>(v)) {
        return TETL_MOVE(*get_if<T>(&v));
    }
    etl::raise<etl::bad_variant_access>("");
}

template <typename... Ts>
template <typename T, typename... Args>
constexpr auto variant<Ts...>::emplace(Args&&... args) -> T&
{
    auto v = variant(etl::in_place_type<T>, TETL_FORWARD(args)...);
    v.swap(*this);
    return *etl::get_if<T>(this);
}

template <typename... Ts>
template <etl::size_t I, typename... Args>
constexpr auto variant<Ts...>::emplace(Args&&... args) -> etl::variant_alternative_t<I, variant>&
{
    auto v = variant(etl::in_place_index<I>, TETL_FORWARD(args)...);
    v.swap(*this);
    return *etl::get_if<I>(this);
}

} // namespace etl

#endif // TETL_VARIANT_VARIANT_HPP
