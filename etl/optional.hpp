/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_OPTIONAL_HPP
#define TETL_OPTIONAL_HPP

/// \file This header is part of the utility library.
/// \example optional.cpp

#include "etl/_config/all.hpp"

#include "etl/_concepts/requires.hpp"
#include "etl/_memory/addressof.hpp"
#include "etl/_new/operator.hpp"
#include "etl/_optional/sfinae_base.hpp"
#include "etl/_type_traits/conjunction.hpp"
#include "etl/_type_traits/decay.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_assignable.hpp"
#include "etl/_type_traits/is_constructible.hpp"
#include "etl/_type_traits/is_copy_assignable.hpp"
#include "etl/_type_traits/is_copy_constructible.hpp"
#include "etl/_type_traits/is_move_assignable.hpp"
#include "etl/_type_traits/is_move_constructible.hpp"
#include "etl/_type_traits/is_nothrow_move_assignable.hpp"
#include "etl/_type_traits/is_nothrow_move_constructible.hpp"
#include "etl/_type_traits/is_nothrow_swappable.hpp"
#include "etl/_type_traits/is_object.hpp"
#include "etl/_type_traits/is_reference.hpp"
#include "etl/_type_traits/is_same.hpp"
#include "etl/_type_traits/is_trivially_copy_assignable.hpp"
#include "etl/_type_traits/is_trivially_copy_constructible.hpp"
#include "etl/_type_traits/is_trivially_destructible.hpp"
#include "etl/_type_traits/is_trivially_move_assignable.hpp"
#include "etl/_type_traits/is_trivially_move_constructible.hpp"
#include "etl/_type_traits/negation.hpp"
#include "etl/_type_traits/remove_cvref.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/in_place.hpp"
#include "etl/_utility/move.hpp"
#include "etl/_utility/swap.hpp"

namespace etl {
/// \brief etl::nullopt_t is an empty class type used to indicate optional type
/// with uninitialized state. In particular, etl::optional has a constructor
/// with nullopt_t as a single argument, which creates an optional that does not
/// contain a value.
struct nullopt_t {
    explicit constexpr nullopt_t(int /*unused*/) { }
};

/// \brief etl::nullopt is a constant of type etl::nullopt_t that is used to
/// indicate optional type with uninitialized state.
inline constexpr auto nullopt = etl::nullopt_t { {} };

namespace detail {
template <typename ValueType,
    bool = etl::is_trivially_destructible_v<ValueType>>
struct optional_destruct_base;

template <typename ValueType>
struct optional_destruct_base<ValueType, false> {
    using value_type = ValueType;
    static_assert(etl::is_object_v<value_type>, "undefined behavior");

    ~optional_destruct_base()
    {
        if (internal_has_value) { internal_value.~value_type(); }
    }

    constexpr optional_destruct_base() noexcept { }

    template <typename... Args>
    constexpr explicit optional_destruct_base(
        etl::in_place_t /*tag*/, Args&&... args)
        : internal_value(etl::forward<Args>(args)...), internal_has_value(true)
    {
    }

    void reset() noexcept
    {
        if (internal_has_value) {
            internal_value.~value_type();
            internal_has_value = false;
        }
    }

    union {
        char internal_null_state {};
        value_type internal_value;
    };

    bool internal_has_value = false;
};

template <typename ValueType>
struct optional_destruct_base<ValueType, true> {
    using value_type = ValueType;
    static_assert(etl::is_object_v<value_type>, "undefined behavior");

    constexpr optional_destruct_base() noexcept { }

    template <typename... Args>
    constexpr explicit optional_destruct_base(
        etl::in_place_t /*unused*/, Args&&... args)
        : internal_value(etl::forward<Args>(args)...), internal_has_value(true)
    {
    }

    void reset() noexcept
    {
        if (internal_has_value) { internal_has_value = false; }
    }

    union {
        char internal_null_state {};
        value_type internal_value;
    };

    bool internal_has_value { false };
};

template <typename ValueType, bool = etl::is_reference_v<ValueType>>
struct optional_storage_base : optional_destruct_base<ValueType> {
    using base_t     = optional_destruct_base<ValueType>;
    using value_type = ValueType;
    using base_t::base_t;

    [[nodiscard]] constexpr auto has_value() const noexcept -> bool
    {
        return this->internal_has_value;
    }

    [[nodiscard]] constexpr auto get() & noexcept -> value_type&
    {
        return this->internal_value;
    }

    [[nodiscard]] constexpr auto get() const& noexcept -> const value_type&
    {
        return this->internal_value;
    }

    [[nodiscard]] constexpr auto get() && noexcept -> value_type&&
    {
        return etl::move(this->internal_value);
    }

    [[nodiscard]] constexpr auto get() const&& noexcept -> const value_type&&
    {
        return etl::move(this->internal_value);
    }

    template <typename... Args>

    void construct(Args&&... args)
    {
        ::new ((void*)etl::addressof(this->internal_value))
            value_type(etl::forward<Args>(args)...);
        this->internal_has_value = true;
    }

    template <typename T>
    void construct_from(T&& opt)
    {
        if (opt.has_value()) { construct(etl::forward<T>(opt).get()); }
    }

    template <typename T>
    void assign_from(T&& opt)
    {
        if (this->internal_has_value == opt.has_value()) {
            if (this->internal_has_value) {
                this->internal_value = etl::forward<T>(opt).get();
            }
        } else {
            if (this->internal_has_value) {
                this->reset();
            } else {
                construct(etl::forward<T>(opt).get());
            }
        }
    }
};

template <typename ValueType,
    bool = etl::is_trivially_copy_constructible_v<ValueType>>
struct optional_copy_base : optional_storage_base<ValueType> {
    using optional_storage_base<ValueType>::optional_storage_base;
};

template <typename ValueType>
struct optional_copy_base<ValueType, false> : optional_storage_base<ValueType> {
    using optional_storage_base<ValueType>::optional_storage_base;

    optional_copy_base() = default;

    optional_copy_base(optional_copy_base const& opt)
        : optional_storage_base<ValueType>::optional_storage_base {}
    {
        this->construct_from(opt);
    }

    optional_copy_base(optional_copy_base&&) noexcept = default;

    auto operator=(optional_copy_base const&) -> optional_copy_base& = default;
    auto operator              =(optional_copy_base&&) noexcept
        -> optional_copy_base& = default;
};

template <typename ValueType,
    bool = etl::is_trivially_move_constructible_v<ValueType>>
struct optional_move_base : optional_copy_base<ValueType> {
    using optional_copy_base<ValueType>::optional_copy_base;
};

template <typename ValueType>
struct optional_move_base<ValueType, false> : optional_copy_base<ValueType> {
    using value_type = ValueType;
    using optional_copy_base<ValueType>::optional_copy_base;

    optional_move_base() = default;

    optional_move_base(optional_move_base const&) = default;

    optional_move_base(optional_move_base&& opt) noexcept(
        etl::is_nothrow_move_constructible_v<value_type>)
    {
        this->construct_from(etl::move(opt));
    }

    auto operator=(optional_move_base const&) -> optional_move_base& = default;

    auto operator              =(optional_move_base&&) noexcept
        -> optional_move_base& = default;
};

template <typename ValueType,
    bool = etl::is_trivially_destructible_v<ValueType>&&
        etl::is_trivially_copy_constructible_v<ValueType>&&
            etl::is_trivially_copy_assignable_v<ValueType>>
struct optional_copy_assign_base : optional_move_base<ValueType> {
    using optional_move_base<ValueType>::optional_move_base;
};

template <typename ValueType>
struct optional_copy_assign_base<ValueType, false>
    : optional_move_base<ValueType> {
    using optional_move_base<ValueType>::optional_move_base;

    optional_copy_assign_base() = default;

    optional_copy_assign_base(optional_copy_assign_base const&) = default;

    optional_copy_assign_base(optional_copy_assign_base&&) noexcept = default;

    [[nodiscard]] auto operator=(optional_copy_assign_base const& opt)
        -> optional_copy_assign_base&
    {
        this->assign_from(opt);
        return *this;
    }

    auto operator                     =(optional_copy_assign_base&&) noexcept
        -> optional_copy_assign_base& = default;
};

template <typename ValueType,
    bool = etl::is_trivially_destructible_v<ValueType>&&
        etl::is_trivially_move_constructible_v<ValueType>&&
            etl::is_trivially_move_assignable_v<ValueType>>
struct optional_move_assign_base : optional_copy_assign_base<ValueType> {
    using optional_copy_assign_base<ValueType>::optional_copy_assign_base;
};

template <typename ValueType>
struct optional_move_assign_base<ValueType, false>
    : optional_copy_assign_base<ValueType> {
    using value_type = ValueType;
    using optional_copy_assign_base<ValueType>::optional_copy_assign_base;

    optional_move_assign_base() = default;

    optional_move_assign_base(optional_move_assign_base const& opt) = default;

    optional_move_assign_base(optional_move_assign_base&&) noexcept = default;

    auto operator                     =(optional_move_assign_base const&)
        -> optional_move_assign_base& = default;

    auto operator=(optional_move_assign_base&& opt) noexcept(
        etl::is_nothrow_move_assignable_v<value_type>&&
            etl::is_nothrow_move_constructible_v<value_type>)
        -> optional_move_assign_base&
    {
        this->assign_from(etl::move(opt));
        return *this;
    }
};

template <typename ValueType>
using optional_sfinae_ctor_base_t
    = sfinae_ctor_base<etl::is_copy_constructible_v<ValueType>,
        etl::is_move_constructible_v<ValueType>>;

template <typename ValueType>
using optional_sfinae_assign_base_t = sfinae_assign_base<
    (etl::is_copy_constructible_v<
         ValueType> && etl::is_copy_assignable_v<ValueType>),
    (etl::is_move_constructible_v<
         ValueType> && etl::is_move_assignable_v<ValueType>)>;

} // namespace detail

template <typename ValueType>
struct optional : private detail::optional_move_assign_base<ValueType>,
                  private detail::optional_sfinae_ctor_base_t<ValueType>,
                  private detail::optional_sfinae_assign_base_t<ValueType> {
private:
    using base_type = detail::optional_move_assign_base<ValueType>;

    static_assert(!is_same_v<remove_cvref_t<ValueType>, in_place_t>,
        "instantiation of optional with in_place_t is ill-formed");
    static_assert(!is_same_v<remove_cvref_t<ValueType>, nullopt_t>,
        "instantiation of optional with nullopt_t is ill-formed");
    static_assert(!is_reference_v<ValueType>,
        "instantiation of optional with a reference type is ill-formed");
    static_assert(!is_array_v<ValueType>,
        "instantiation of optional with an array type is ill-formed");

public:
    using value_type = ValueType;

    /// \brief Constructs an object that does not contain a value.
    constexpr optional() noexcept = default;

    /// \brief Constructs an object that does not contain a value.
    constexpr optional(etl::nullopt_t /*unused*/) noexcept { }

    /// \brief Copy constructor.
    constexpr optional(optional const&) = default;

    /// \brief Move constructor.
    constexpr optional(optional&&) noexcept(
        etl::is_nothrow_move_constructible_v<value_type>)
        = default;

    /// \brief Constructs an optional object that contains a value, initialized
    /// as if direct-initializing.
    template <typename... Args,
        TETL_REQUIRES_((is_constructible_v<value_type, Args...>))>
    constexpr explicit optional(in_place_t /*unused*/, Args&&... arguments)
        : base_type(in_place, forward<Args>(arguments)...)
    {
    }

    /// \brief Constructs an optional object that contains a value, initialized
    /// as if direct-initializing.
    template <typename U = value_type,
        typename = enable_if_t<conjunction_v<is_constructible<ValueType, U&&>,
            negation<is_same<remove_cvref_t<U>, optional<ValueType>>>,
            negation<is_same<remove_cvref_t<U>, in_place_t>>>>>
    constexpr optional(U&& value) : base_type(in_place, forward<U>(value))
    {
    }

    /// \brief If *this contains a value before the call, the contained value is
    /// destroyed by calling its destructor as if by value().T::~T(). *this does
    /// not contain a value after this call.
    constexpr auto operator=(etl::nullopt_t /*unused*/) noexcept -> optional&
    {
        reset();
        return *this;
    }

    /// \brief Assigns the state of other.
    constexpr auto operator=(optional const& other) -> optional&
    {
        this->assign_from(other);
        return *this;
    }

    /// \brief Perfect-forwarded assignment.
    ///
    /// \todo Cleanup & fix SFINAE.
    template <typename U = ValueType>
    constexpr auto operator=(U&& value) -> etl::enable_if_t<
        etl::conjunction_v<etl::negation<etl::is_same<etl::remove_cvref_t<U>,
                               etl::optional<ValueType>>>,
            etl::is_constructible<ValueType, U>,
            etl::is_assignable<ValueType&, U>>,
        // && (!etl::is_scalar_v<ValueType> || !etl::is_same_v<etl::decay_t<U>,
        // ValueType>),
        optional&>
    {
        if (this->has_value()) {
            this->get() = etl::forward<U>(value);
            return *this;
        }

        this->construct(etl::forward<U>(value));
        return *this;
    }

    /// \brief Checks whether *this contains a value.
    using base_type::has_value;

    /// \brief Checks whether *this contains a value.
    [[nodiscard]] constexpr explicit operator bool() const noexcept
    {
        return has_value();
    }

    /// \brief If *this contains a value, destroy that value as if by
    /// value().~value_type(). Otherwise, there are no effects. *this does not
    /// contain a value after this call.
    using base_type::reset;

    /// \brief If the optional contains a value, returns a pointer. If empty the
    /// pointer will be null.
    [[nodiscard]] constexpr auto value() -> value_type*
    {
        return this->has_value() ? &this->get() : nullptr;
    }

    /// \brief If the optional contains a value, returns a pointer. If empty the
    /// pointer will be null.
    [[nodiscard]] constexpr auto value() const -> const value_type*
    {
        return this->has_value() ? &this->get() : nullptr;
    }

    /// \brief Returns the contained value if *this has a value, otherwise
    /// returns default_value.
    template <typename U>
    [[nodiscard]] constexpr auto value_or(U&& defaultValue) const& -> value_type
    {
        return has_value()
                   ? *this->value()
                   : static_cast<value_type>(etl::forward<U>(defaultValue));
    }

    /// \brief Returns the contained value if *this has a value, otherwise
    /// returns default_value.
    template <typename U>
    [[nodiscard]] constexpr auto value_or(U&& defaultValue) && -> value_type
    {
        return has_value()
                   ? etl::move(*this->value())
                   : static_cast<value_type>(etl::forward<U>(defaultValue));
    }

    /// \brief Returns a pointer to the contained value. The pointer is null if
    /// the optional is empty.
    [[nodiscard]] constexpr auto operator->() const -> const value_type*
    {
        return this->value();
    }

    /// \brief Returns a pointer to the contained value. The pointer is null if
    /// the optional is empty.
    [[nodiscard]] constexpr auto operator->() -> value_type*
    {
        return this->value();
    }

    /// \brief Swaps the contents with those of other.
    constexpr auto swap(optional& other) noexcept(
        etl::is_nothrow_move_constructible_v<value_type>&&
            etl::is_nothrow_swappable_v<value_type>) -> void
    {
        // If neither *this nor other contain a value, the function has no
        // effect.

        // If both *this and other contain values, the contained values are
        // exchanged
        if (this->has_value() == other.has_value()) {
            using etl::swap;
            if (this->has_value()) { swap(this->get(), other.get()); }
            return;
        }

        // If only one of *this and other contains a value (let's call this
        // object in and the other un), the contained value of un is
        // direct-initialized from etl::move(*in), followed by destruction of
        // the contained value of in as if by in->T::~T(). After this call, in
        // does not contain a value; un contains a value.
        if (this->has_value()) {
            other.construct(etl::move(this->get()));
            reset();
            return;
        }

        this->construct(etl::move(other.get()));
        other.reset();
    }

    /// \brief Constructs the contained value in-place. If *this already
    /// contains a value before the call, the contained value is destroyed by
    /// calling its destructor.
    template <typename... Args>
    constexpr auto emplace(Args&&... args) -> value_type&
    {
        this->reset();
        this->construct(etl::forward<Args>(args)...);
        return *value();
    }

    /// \brief Implementation detail. Do not use!
    using base_type::get;
};

/// \brief Compares two optional objects, lhs and rhs.
template <typename T, typename U>
[[nodiscard]] constexpr auto operator==(
    optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (static_cast<bool>(lhs) != static_cast<bool>(rhs)) { return false; }
    if (!static_cast<bool>(lhs) && !static_cast<bool>(rhs)) { return true; }
    return *lhs.value() == *rhs.value();
}

/// \brief Compares two optional objects, lhs and rhs.
template <typename T, typename U>
[[nodiscard]] constexpr auto operator!=(
    optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (static_cast<bool>(lhs) != static_cast<bool>(rhs)) { return true; }
    if (!static_cast<bool>(lhs) && !static_cast<bool>(rhs)) { return false; }
    return *lhs.value() != *rhs.value();
}

/// \brief Compares two optional objects, lhs and rhs.
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<(
    optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (!static_cast<bool>(rhs)) { return false; }
    if (!static_cast<bool>(lhs)) { return true; }
    return *lhs.value() < *rhs.value();
}

/// \brief Compares two optional objects, lhs and rhs.
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>(
    optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (!static_cast<bool>(lhs)) { return false; }
    if (!static_cast<bool>(rhs)) { return true; }
    return *lhs.value() > *rhs.value();
}

/// \brief Compares two optional objects, lhs and rhs.
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<=(
    optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (!static_cast<bool>(lhs)) { return true; }
    if (!static_cast<bool>(rhs)) { return false; }
    return *lhs.value() <= *rhs.value();
}

/// \brief Compares two optional objects, lhs and rhs.
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>=(
    optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (!static_cast<bool>(rhs)) { return true; }
    if (!static_cast<bool>(lhs)) { return false; }
    return *lhs.value() >= *rhs.value();
}

/// \brief Compares opt with a nullopt. Equivalent to when comparing to an
/// optional that does not contain a value.
template <typename T>
[[nodiscard]] constexpr auto operator==(
    optional<T> const& opt, etl::nullopt_t /*unused*/) noexcept -> bool
{
    return !opt;
}

/// \brief Compares opt with a nullopt. Equivalent to when comparing to an
/// optional that does not contain a value.
template <typename T>
[[nodiscard]] constexpr auto operator==(
    etl::nullopt_t /*unused*/, optional<T> const& opt) noexcept -> bool
{
    return !opt;
}

/// \brief Compares opt with a nullopt. Equivalent to when comparing to an
/// optional that does not contain a value.
template <typename T>
[[nodiscard]] constexpr auto operator!=(
    optional<T> const& opt, etl::nullopt_t /*unused*/) noexcept -> bool
{
    return static_cast<bool>(opt);
}

/// \brief Compares opt with a nullopt. Equivalent to when comparing to an
/// optional that does not contain a value.
template <typename T>
[[nodiscard]] constexpr auto operator!=(
    etl::nullopt_t /*unused*/, optional<T> const& opt) noexcept -> bool
{
    return static_cast<bool>(opt);
}

/// \brief Compares opt with a nullopt. Equivalent to when comparing to an
/// optional that does not contain a value.
template <typename T>
[[nodiscard]] constexpr auto operator<(
    optional<T> const& /*opt*/, etl::nullopt_t /*unused*/) noexcept -> bool
{
    return false;
}

/// \brief Compares opt with a nullopt. Equivalent to when comparing to an
/// optional that does not contain a value.
template <typename T>
[[nodiscard]] constexpr auto operator<(
    etl::nullopt_t /*unused*/, optional<T> const& opt) noexcept -> bool
{
    return static_cast<bool>(opt);
}

/// \brief Compares opt with a nullopt. Equivalent to when comparing to an
/// optional that does not contain a value.
template <typename T>
[[nodiscard]] constexpr auto operator<=(
    optional<T> const& opt, etl::nullopt_t /*unused*/) noexcept -> bool
{
    return !opt;
}

/// \brief Compares opt with a nullopt. Equivalent to when comparing to an
/// optional that does not contain a value.
template <typename T>
[[nodiscard]] constexpr auto operator<=(
    etl::nullopt_t /*unused*/, optional<T> const& /*opt*/) noexcept -> bool
{
    return true;
}

/// \brief Compares opt with a nullopt. Equivalent to when comparing to an
/// optional that does not contain a value.
template <typename T>
[[nodiscard]] constexpr auto operator>(
    optional<T> const& opt, etl::nullopt_t /*unused*/) noexcept -> bool
{
    return static_cast<bool>(opt);
}

/// \brief Compares opt with a nullopt. Equivalent to when comparing to an
/// optional that does not contain a value.
template <typename T>
[[nodiscard]] constexpr auto operator>(
    etl::nullopt_t /*unused*/, optional<T> const& /*opt*/) noexcept -> bool
{
    return false;
}

/// \brief Compares opt with a nullopt. Equivalent to when comparing to an
/// optional that does not contain a value.
template <typename T>
[[nodiscard]] constexpr auto operator>=(
    optional<T> const& /*opt*/, etl::nullopt_t /*unused*/) noexcept -> bool
{
    return true;
}

/// \brief Compares opt with a nullopt. Equivalent to when comparing to an
/// optional that does not contain a value.
template <typename T>
[[nodiscard]] constexpr auto operator>=(
    etl::nullopt_t /*unused*/, optional<T> const& opt) noexcept -> bool
{
    return !opt;
}

//
// /// \brief Compares opt with a value. The values are compared (using the
//  corresponding
// /// operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
// /// value. If the corresponding two-way comparison expression between *opt
// and
//  value is not
// /// well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
// template <typename T, typename U>
// constexpr auto operator==(optional<T> const&, U const &) -> bool
// {
// }

//
// /// \brief Compares opt with a value. The values are compared (using the
//  corresponding
// /// operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
// /// value. If the corresponding two-way comparison expression between *opt
// and
//  value is not
// /// well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
// template <typename T, typename U>
// constexpr auto operator==(T const&, optional<U> const&) -> bool
// {
// }

//
// /// \brief Compares opt with a value. The values are compared (using the
//  corresponding
// /// operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
// /// value. If the corresponding two-way comparison expression between *opt
// and
//  value is not
// /// well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
// template <typename T, typename U>
// constexpr auto operator!=(optional<T> const&, U const&) -> bool
// {
// }

//
// /// \brief Compares opt with a value. The values are compared (using the
//  corresponding
// /// operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
// /// value. If the corresponding two-way comparison expression between *opt
// and
//  value is not
// /// well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
// template <typename T, typename U>
// constexpr auto operator!=(T const&, optional<U> const&) -> bool
// {
// }

//
// /// \brief Compares opt with a value. The values are compared (using the
//  corresponding
// /// operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
// /// value. If the corresponding two-way comparison expression between *opt
// and
//  value is not
// /// well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
// template <typename T, typename U>
// constexpr auto operator<(optional<T> const&, U const&) -> bool
// {
// }

//
// /// \brief Compares opt with a value. The values are compared (using the
//  corresponding
// /// operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
// /// value. If the corresponding two-way comparison expression between *opt
// and
//  value is not
// /// well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
// template <typename T, typename U>
// constexpr auto operator<(T const&, optional<U> const&) -> bool
// {
// }

//
// /// \brief Compares opt with a value. The values are compared (using the
//  corresponding
// /// operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
// /// value. If the corresponding two-way comparison expression between *opt
// and
//  value is not
// /// well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
// template <typename T, typename U>
// constexpr auto operator>(optional<T> const&, U const&) -> bool
// {
// }

//
// /// \brief Compares opt with a value. The values are compared (using the
//  corresponding
// /// operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
// /// value. If the corresponding two-way comparison expression between *opt
// and
//  value is not
// /// well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
// template <typename T, typename U>
// constexpr auto operator>(T const&, optional<U> const&) -> bool
// {
// }

//
// /// \brief Compares opt with a value. The values are compared (using the
//  corresponding
// /// operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
// /// value. If the corresponding two-way comparison expression between *opt
// and
//  value is not
// /// well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
// template <typename T, typename U>
// constexpr auto operator<=(optional<T> const&, U const&) -> bool
// {
// }

//
// /// \brief Compares opt with a value. The values are compared (using the
//  corresponding
// /// operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
// /// value. If the corresponding two-way comparison expression between *opt
// and
//  value is not
// /// well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
// template <typename T, typename U>
// constexpr auto operator<=(T const&, optional<U> const&) -> bool
// {
// }

//
// /// \brief Compares opt with a value. The values are compared (using the
//  corresponding
// /// operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
// /// value. If the corresponding two-way comparison expression between *opt
// and
//  value is not
// /// well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
// template <typename T, typename U>
// constexpr auto operator>=(optional<T> const&, U const&) -> bool
// {
// }

//
// /// \brief Compares opt with a value. The values are compared (using the
//  corresponding
// /// operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
// /// value. If the corresponding two-way comparison expression between *opt
// and
//  value is not
// /// well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
// template <typename T, typename U>
// constexpr auto operator>=(T const&, optional<U> const&) -> bool
// {
// }

/// \brief Creates an optional object from value.
template <typename ValueType>
constexpr auto make_optional(ValueType&& value)
    -> etl::optional<etl::decay_t<ValueType>>
{
    return etl::optional<etl::decay_t<ValueType>>(
        etl::forward<ValueType>(value));
}

/// \brief Creates an optional object constructed in-place from args...
template <typename ValueType, typename... Args>
constexpr auto make_optional(Args&&... args) -> etl::optional<ValueType>
{
    return etl::optional<ValueType>(etl::in_place, etl::forward<Args>(args)...);
}

// One deduction guide is provided for etl::optional to account for the
// edge cases missed by the implicit deduction guides, in particular,
// non-copyable arguments and array to pointer conversion.
template <typename T>
optional(T) -> optional<T>;

} // namespace etl
#endif // TETL_OPTIONAL_HPP