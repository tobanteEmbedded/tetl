/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_VARIANT_VARIANT_HPP
#define TETL_VARIANT_VARIANT_HPP

#include "etl/_array/array.hpp"
#include "etl/_concepts/requires.hpp"
#include "etl/_cstddef/size_t.hpp"
#include "etl/_new/operator.hpp"
#include "etl/_type_traits/add_pointer.hpp"
#include "etl/_type_traits/aligned_storage.hpp"
#include "etl/_type_traits/index_sequence.hpp"
#include "etl/_type_traits/integral_constant.hpp"
#include "etl/_type_traits/is_nothrow_move_constructible.hpp"
#include "etl/_type_traits/is_nothrow_swappable.hpp"
#include "etl/_type_traits/is_same.hpp"
#include "etl/_type_traits/type_pack_element.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/move.hpp"
#include "etl/_utility/swap.hpp"
#include "etl/_variant/monostate.hpp"
#include "etl/_variant/variant_alternative.hpp"
#include "etl/_variant/variant_fwd.hpp"
#include "etl/_variant/variant_size.hpp"
#include "etl/_warning/ignore_unused.hpp"

namespace etl {

namespace detail {

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

template <typename...>
struct variant_storage;

template <typename Head>
struct variant_storage<Head> {
    using storage_t = etl::aligned_storage_t<sizeof(Head), alignof(Head)>;
    storage_t data;

    template <typename T>
    void construct(T&& headInit, etl::size_t& index)
    {
        static_assert(etl::is_same_v<T, Head>,
            "Tried to access non-existent type in union");
        new (&data) Head(etl::forward<T>(headInit));
        index = 0;
    }

    void destruct(etl::size_t /*unused*/)
    {
        static_cast<Head*>(static_cast<void*>(&data))->~Head();
    }
};

template <typename Head, typename... Tail>
struct variant_storage<Head, Tail...> {
    using storage_t = etl::aligned_storage_t<sizeof(Head), alignof(Head)>;

    union {
        storage_t data;
        variant_storage<Tail...> tail;
    };

    void construct(Head const& headInit, etl::size_t& index)
    {
        new (&data) Head(headInit);
        index = 0;
    }

    void construct(Head& headInit, etl::size_t& index)
    {
        const auto& headCref = headInit;
        construct(headCref, index);
    }

    void construct(Head&& headInit, etl::size_t& index)
    {
        using etl::move;
        new (&data) Head(move(headInit));
        index = 0;
    }

    template <typename T>
    void construct(T&& t, etl::size_t& index)
    {
        tail.construct(etl::forward<T>(t), index);
        ++index;
    }

    void destruct(etl::size_t index)
    {
        if (index == 0) {
            static_cast<Head*>(static_cast<void*>(&data))->~Head();
            return;
        }

        tail.destruct(index - 1);
    }
};
template <typename...>
struct variant_storage_type_get;

template <typename Head, typename... Tail>
struct variant_storage_type_get<Head, variant_storage<Head, Tail...>> {
    static auto get(variant_storage<Head, Tail...>& vu) -> Head&
    {
        return *static_cast<Head*>(static_cast<void*>(&vu.data));
    }

    static auto get(variant_storage<Head, Tail...> const& vu) -> Head const&
    {
        return *static_cast<Head const*>(static_cast<void const*>(&vu.data));
    }

    static constexpr const etl::size_t index = 0;
};

template <typename Target, typename Head, typename... Tail>
struct variant_storage_type_get<Target, variant_storage<Head, Tail...>> {
    static auto get(variant_storage<Head, Tail...>& vu) -> Target&
    {
        return variant_storage_type_get<Target, variant_storage<Tail...>>::get(
            vu.tail);
    }

    static auto get(variant_storage<Head, Tail...> const& vu) -> Target const&
    {
        return variant_storage_type_get<Target, variant_storage<Tail...>>::get(
            vu.tail);
    }

    static constexpr const etl::size_t index
        = variant_storage_type_get<Target, variant_storage<Tail...>>::index + 1;
};

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
    /// \brief Converting constructor.
    /// \details Constructs a variant holding the alternative type T.
    template <typename T>
    explicit variant(T&& t)
    {
        data_.construct(etl::forward<T>(t), index_);
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
        // The behavior is undefined unless lvalues of type T_i are Swappable
        // and is_move_constructible_v<T_i> is true for all T_i in Types....
        static_assert(detail::enable_variant_swap<Types...>);

        if (valueless_by_exception() && rhs.valueless_by_exception()) {
            return;
        }
        if (index() == rhs.index()) {
            detail::variant_swap_table<variant, Types...>[index()](*this, rhs);
        }
    }

    /// \todo Remove & replace with friendship for etl::get_if.
    [[nodiscard]] auto data() const noexcept { return &data_; }
    auto data() noexcept { return &data_; }

private:
    detail::variant_storage<Types...> data_;
    etl::size_t index_;
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

/// \brief Checks if the variant v holds the alternative T. The call is
/// ill-formed if T does not appear exactly once in Types...
template <typename T, typename... Types>
constexpr auto holds_alternative(etl::variant<Types...> const& v) noexcept
    -> bool
{
    using storage_t = detail::variant_storage<Types...>;
    return detail::variant_storage_type_get<T, storage_t>::index == v.index();
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
    etl::ignore_unused(pv);
    return nullptr;
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
    etl::ignore_unused(pv);
    return nullptr;
}

/// \brief Type-based non-throwing accessor: The call is ill-formed if T is not
/// a unique element of Types....
template <typename T, typename... Types>
constexpr auto get_if(etl::variant<Types...>* pv) noexcept
    -> etl::add_pointer_t<T>
{
    if (holds_alternative<T>(*pv)) {
        using storage_t = detail::variant_storage<Types...>;
        return &detail::variant_storage_type_get<T, storage_t>::get(
            *pv->data());
    }

    return nullptr;
}

/// \brief Type-based non-throwing accessor: The call is ill-formed if T is not
/// a unique element of Types....
template <typename T, typename... Types>
constexpr auto get_if(etl::variant<Types...> const* pv) noexcept
    -> etl::add_pointer_t<const T>
{
    if (holds_alternative<T>(*pv)) {
        using storage_t = detail::variant_storage<Types...>;
        return &detail::variant_storage_type_get<T, storage_t>::get(
            *pv->data());
    }

    return nullptr;
}

} // namespace etl

#endif // TETL_VARIANT_VARIANT_HPP