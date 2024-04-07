// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_OPTIONAL_OPTIONAL_HPP
#define TETL_OPTIONAL_OPTIONAL_HPP

#include <etl/_config/all.hpp>

#include <etl/_concepts/copy_constructible.hpp>
#include <etl/_concepts/move_constructible.hpp>
#include <etl/_concepts/same_as.hpp>
#include <etl/_contracts/check.hpp>
#include <etl/_functional/hash.hpp>
#include <etl/_functional/invoke.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_optional/nullopt.hpp>
#include <etl/_type_traits/add_lvalue_reference.hpp>
#include <etl/_type_traits/conjunction.hpp>
#include <etl/_type_traits/decay.hpp>
#include <etl/_type_traits/invoke_result.hpp>
#include <etl/_type_traits/is_assignable.hpp>
#include <etl/_type_traits/is_constructible.hpp>
#include <etl/_type_traits/is_convertible.hpp>
#include <etl/_type_traits/is_lvalue_reference.hpp>
#include <etl/_type_traits/is_nothrow_move_constructible.hpp>
#include <etl/_type_traits/is_nothrow_swappable.hpp>
#include <etl/_type_traits/is_same.hpp>
#include <etl/_type_traits/is_scalar.hpp>
#include <etl/_type_traits/is_specialized.hpp>
#include <etl/_type_traits/remove_const.hpp>
#include <etl/_type_traits/remove_cv.hpp>
#include <etl/_type_traits/remove_cvref.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/in_place.hpp>
#include <etl/_utility/in_place_index.hpp>
#include <etl/_utility/move.hpp>
#include <etl/_utility/swap.hpp>
#include <etl/_variant/monostate.hpp>
#include <etl/_variant/variant.hpp>

namespace etl {

/// \brief The class template optional manages an optional contained value,
/// i.e. a value that may or may not be present.
///
/// \details A common use case for optional is the return value of a function
/// that may fail. As opposed to other approaches, such as etl::pair<T,bool>,
/// optional handles expensive-to-construct objects well and is more readable,
/// as the intent is expressed explicitly.
///
/// Any instance of optional at any given point in time either contains a
/// value or does not contain a value.
///
/// If an optional contains a value, the value is guaranteed to be
/// allocated as part of the optional object footprint, i.e. no dynamic memory
/// allocation ever takes place. Thus, an optional object models an object, not
/// a pointer, even though operator*() and operator->() are defined.
///
/// When an object of type optional is contextually converted to bool, the
/// conversion returns true if the object contains a value and false if it does
/// not contain a value.
///
/// The optional object contains a value in the following conditions:
///     - The object is initialized with/assigned from a value of type T or
///     another optional that contains a value.
///
/// The object does not contain a value in the following conditions:
///     - The object is default-initialized.
///     - The object is initialized with/assigned from a value of type
///     etl::nullopt_t or an optional object that does not contain a value.
///     - The member function reset() is called.
///
/// There are no optional references; a program is ill-formed if it instantiates
/// an optional with a reference type. Alternatively, an optional of a
/// etl::reference_wrapper of type T may be used to hold a reference. In
/// addition, a program is ill-formed if it instantiates an optional with the
/// (possibly cv-qualified) tag types etl::nullopt_t or etl::in_place_t.
///
/// https://en.cppreference.com/w/cpp/utility/optional
///
/// \tparam T The type of the value to manage initialization state for. The type
/// must meet the requirements of Destructible (in particular, array types are
/// not allowed).
///
/// \headerfile etl/optional.hpp
/// \ingroup optional
///
/// \include optional.cpp
template <typename T>
struct optional {
    using value_type = T;

    static_assert(!is_array_v<T>, "instantiation of optional with an array type is ill-formed");
    static_assert(!is_same_v<remove_cvref_t<T>, nullopt_t>, "instantiation of optional with nullopt_t is ill-formed");
    static_assert(!is_same_v<remove_cvref_t<T>, in_place_t>, "instantiation of optional with in_place_t is ill-formed");

    /// Constructs an object that does not contain a value.
    constexpr optional() noexcept = default;

    /// Constructs an object that does not contain a value.
    constexpr optional(nullopt_t /*null*/) noexcept { }

    /// Copy constructor.
    constexpr optional(optional const&) = default;

    /// Move constructor.
    constexpr optional(optional&&) noexcept(is_nothrow_move_constructible_v<value_type>) = default;

    /// Converting copy constructor
    ///
    /// If other doesn't contain a value, constructs an optional object
    /// that does not contain a value. Otherwise, constructs an optional
    /// object that contains a value, initialized as if direct-initializing
    /// (but not direct-list-initializing) an object of type T with the
    /// expression *other.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/optional
    template <typename U>
    // clang-format off
        requires (
                    is_constructible_v<T, U const&>
            and not is_same_v<remove_cv_t<U>, bool>
            and not is_constructible_v<T, optional<U>&>
            and not is_constructible_v<T, optional<U> const&>
            and not is_constructible_v<T, optional<U> &&>
            and not is_constructible_v<T, optional<U> const&&>
            and not is_convertible_v<optional<U>&, T>
            and not is_convertible_v<optional<U> const&, T>
            and not is_convertible_v<optional<U>&&, T>
            and not is_convertible_v<optional<U> const&&, T>

        )
    // clang-format on
    explicit(not is_convertible_v<U const&, T>) constexpr optional(optional<U> const& other)
    {
        if (other.has_value()) {
            emplace(*other);
        }
    }

    /// Converting move constructor
    ///
    /// If other doesn't contain a value, constructs an optional object that does
    /// not contain a value. Otherwise, constructs an optional object that contains a value,
    /// initialized as if direct-initializing (but not direct-list-initializing)
    /// an object of type T with the expression etl::move(*other).
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/optional
    template <typename U>
    // clang-format off
        requires (
                    is_constructible_v<T, U&&>
            and not is_same_v<remove_cv_t<U>, bool>
            and not is_constructible_v<T, optional<U>&>
            and not is_constructible_v<T, optional<U> const&>
            and not is_constructible_v<T, optional<U> &&>
            and not is_constructible_v<T, optional<U> const&&>
            and not is_convertible_v<optional<U>&, T>
            and not is_convertible_v<optional<U> const&, T>
            and not is_convertible_v<optional<U>&&, T>
            and not is_convertible_v<optional<U> const&&, T>
        )
    // clang-format on
    explicit(not is_convertible_v<U&&, T>) constexpr optional(optional<U>&& other)
    {
        if (other.has_value()) {
            emplace(*etl::move(other));
        }
    }

    /// Constructs an optional object that contains a value,
    /// initialized as if direct-initializing.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/optional
    template <typename... Args>
        requires is_constructible_v<T, Args...>
    constexpr explicit optional(in_place_t /*tag*/, Args&&... args)
        : _var(in_place_index<1>, etl::forward<Args>(args)...)
    {
    }

    /// Constructs an optional object that contains a value,
    /// initialized as if direct-initializing.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/optional
    template <typename U = T>
    // clang-format off
        requires (
            is_constructible_v<T, U &&>
            and not is_same_v<remove_cvref_t<U>, in_place_t>
            and not is_same_v<remove_cvref_t<U>, optional>
        )
    // clang-format on
    explicit(not is_convertible_v<U&&, T>) constexpr optional(U&& value)
        : _var(in_place_index<1>, etl::forward<U>(value))
    {
    }

    /// If *this contains a value before the call, the contained value is
    /// destroyed by calling its destructor as if by value().T::~T(). *this does
    /// not contain a value after this call.
    constexpr auto operator=(etl::nullopt_t /*unused*/) noexcept -> optional&
    {
        reset();
        return *this;
    }

    /// Assigns the state of other.
    constexpr auto operator=(optional const& other) -> optional& = default;

    /// Assigns the state of other.
    constexpr auto operator=(optional&& other) noexcept -> optional& = default;

    /// Perfect-forwarded assignment.
    ///
    /// Depending on whether *this contains a value before the call,
    /// the contained value is either direct-initialized from
    /// etl::forward<U>(value) or assigned from etl::forward<U>(value).
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/operator%3D
    template <typename U = T>
    // clang-format off
        requires (
                    is_assignable_v<T&, U>
            and     is_constructible_v<T, U>
            and not is_same_v<optional, decay_t<U>>
            and not is_scalar_v<T>
            and not is_same_v<T, decay_t<U>>
        )
    // clang-format on
    constexpr auto operator=(U&& value) -> optional&
    {
        emplace(etl::forward<U>(value));
        return *this;
    }

    /// Assigns the state of other.
    template <typename U = T>
    // clang-format off
        requires (
                    is_constructible_v<T, U const&>
                and is_assignable_v<T&, U const&>
            and not is_constructible_v<T, optional<U>&>
            and not is_constructible_v<T, optional<U> const&>
            and not is_constructible_v<T, optional<U>&&>
            and not is_constructible_v<T, optional<U> const&&>
            and not is_convertible_v<optional<U>&, T>
            and not is_convertible_v<optional<U> const&, T>
            and not is_convertible_v<optional<U>&&, T>
            and not is_convertible_v<optional<U> const&&, T>
            and not is_assignable_v<T&, optional<U>&>
            and not is_assignable_v<T&, optional<U> const&>
            and not is_assignable_v<T&, optional<U>&&>
            and not is_assignable_v<T&, optional<U> const&&>
        )
    // clang-format on
    constexpr auto operator=(optional<U> const& other) -> optional&
    {
        if (other.has_value()) {
            emplace(*other);
        } else {
            reset();
        }

        return *this;
    }

    /// Assigns the state of other.
    template <typename U = T>
    // clang-format off
        requires (
                    is_constructible_v<T, U>
                and is_assignable_v<T&, U>
            and not is_constructible_v<T, optional<U>&>
            and not is_constructible_v<T, optional<U> const&>
            and not is_constructible_v<T, optional<U>&&>
            and not is_constructible_v<T, optional<U> const&&>
            and not is_convertible_v<optional<U>&, T>
            and not is_convertible_v<optional<U> const&, T>
            and not is_convertible_v<optional<U>&&, T>
            and not is_convertible_v<optional<U> const&&, T>
            and not is_assignable_v<T&, optional<U>&>
            and not is_assignable_v<T&, optional<U> const&>
            and not is_assignable_v<T&, optional<U>&&>
            and not is_assignable_v<T&, optional<U> const&&>
        )
    // clang-format on
    constexpr auto operator=(optional<U>&& other) -> optional&
    {
        if (other.has_value()) {
            emplace(*etl::move(other));
        } else {
            reset();
        }

        return *this;
    }

    /// Checks whether *this contains a value.
    [[nodiscard]] constexpr auto has_value() const noexcept -> bool { return _var.index() == 1; }

    /// Checks whether *this contains a value.
    [[nodiscard]] constexpr explicit operator bool() const noexcept { return has_value(); }

    /// If *this contains a value, destroy that value as if by
    /// value().~value_type(). Otherwise, there are no effects. *this does not
    /// contain a value after this call.
    constexpr auto reset() noexcept -> void { _var.template emplace<0>(nullopt); }

    /// Returns the contained value if *this has a value, otherwise
    /// returns default_value.
    template <typename U>
    [[nodiscard]] constexpr auto value_or(U&& defaultValue) const& -> value_type
    {
        return has_value() ? (**this) : static_cast<value_type>(etl::forward<U>(defaultValue));
    }

    /// Returns the contained value if *this has a value, otherwise
    /// returns default_value.
    template <typename U>
    [[nodiscard]] constexpr auto value_or(U&& defaultValue) && -> value_type
    {
        return has_value() ? etl::move((**this)) : static_cast<value_type>(etl::forward<U>(defaultValue));
    }

    /// Returns a pointer to the contained value. The pointer is null if
    /// the optional is empty.
    [[nodiscard]] constexpr auto operator->() const -> value_type const* { return etl::get_if<1>(&_var); }

    /// Returns a pointer to the contained value. The pointer is null if
    /// the optional is empty.
    [[nodiscard]] constexpr auto operator->() -> value_type* { return etl::get_if<1>(&_var); }

    /// Returns a reference to the contained value.
    ///
    /// \details This operator only checks whether the optional contains a
    /// value in debug builds! You can do so manually by using has_value() or
    /// simply operator bool(). Alternatively, if checked access is needed,
    /// value() or value_or() may be used.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/operator*
    [[nodiscard]] constexpr auto operator*() const& -> T const&
    {
        TETL_PRECONDITION(has_value());
        return etl::unchecked_get<1>(_var);
    }

    /// Returns a reference to the contained value.
    ///
    /// \details This operator only checks whether the optional contains a
    /// value in debug builds! You can do so manually by using has_value() or
    /// simply operator bool(). Alternatively, if checked access is needed,
    /// value() or value_or() may be used.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/operator*
    [[nodiscard]] constexpr auto operator*() & -> T&
    {
        TETL_PRECONDITION(has_value());
        return etl::unchecked_get<1>(_var);
    }

    /// Returns a reference to the contained value.
    ///
    /// \details This operator only checks whether the optional contains a
    /// value in debug builds! You can do so manually by using has_value() or
    /// simply operator bool(). Alternatively, if checked access is needed,
    /// value() or value_or() may be used.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/operator*
    [[nodiscard]] constexpr auto operator*() const&& -> T const&&
    {
        TETL_PRECONDITION(has_value());
        return etl::move(etl::unchecked_get<1>(_var));
    }

    /// Returns a reference to the contained value.
    ///
    /// \details This operator only checks whether the optional contains a
    /// value in debug builds! You can do so manually by using has_value() or
    /// simply operator bool(). Alternatively, if checked access is needed,
    /// value() or value_or() may be used.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/operator*
    [[nodiscard]] constexpr auto operator*() && -> T&&
    {
        TETL_PRECONDITION(has_value());
        return etl::move(etl::unchecked_get<1>(_var));
    }

    /// Swaps the contents with those of other.
    constexpr auto swap(optional& other)
        noexcept(is_nothrow_move_constructible_v<value_type> and is_nothrow_swappable_v<value_type>) -> void
    {
        etl::swap(*this, other);
    }

    /// Constructs the contained value in-place. If *this already
    /// contains a value before the call, the contained value is destroyed by
    /// calling its destructor.
    template <typename... Args>
    constexpr auto emplace(Args&&... args) -> value_type&
    {
        return _var.template emplace<1>(etl::forward<Args>(args)...);
    }

    template <typename F>
    constexpr auto and_then(F&& f) &
    {
        if (*this) {
            return etl::invoke(etl::forward<F>(f), **this);
        }
        return remove_cvref_t<invoke_result_t<F, T&>>{};
    }

    template <typename F>
    constexpr auto and_then(F&& f) const&
    {
        if (*this) {
            return etl::invoke(etl::forward<F>(f), **this);
        }
        return remove_cvref_t<invoke_result_t<F, T const&>>{};
    }

    template <typename F>
    constexpr auto and_then(F&& f) &&
    {
        if (*this) {
            return etl::invoke(etl::forward<F>(f), etl::move(**this));
        }
        return remove_cvref_t<invoke_result_t<F, T>>{};
    }

    template <typename F>
    constexpr auto and_then(F&& f) const&&
    {
        if (*this) {
            return etl::invoke(etl::forward<F>(f), etl::move(**this));
        }
        return remove_cvref_t<invoke_result_t<F, T const>>{};
    }

    template <typename F>
        requires(copy_constructible<T> and same_as<remove_cvref_t<invoke_result_t<F>>, optional>)
    constexpr auto or_else(F&& f) const& -> optional
    {
        return *this ? *this : etl::forward<F>(f)();
    }

    template <typename F>
        requires(move_constructible<T> and same_as<remove_cvref_t<invoke_result_t<F>>, optional>)
    constexpr auto or_else(F&& f) && -> optional
    {
        return *this ? etl::move(*this) : etl::forward<F>(f)();
    }

private:
    variant<nullopt_t, T> _var{nullopt};
};

// https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2024/p2988r3.pdf
template <typename T>
struct optional<T&> {
    using value_type = T&;

    constexpr optional() noexcept = default;

    constexpr optional(nullopt_t /*tag*/) noexcept
        : _ptr{nullptr}
    {
    }

    template <typename U = T>
        requires(not is_same_v<remove_cvref_t<U>, optional>)
    constexpr explicit(not is_convertible_v<U, T>) optional(U&& v)
        : _ptr(etl::addressof(v))
    {
        static_assert(is_constructible_v<add_lvalue_reference_t<T>, U>, "Must be able to bind U to T&");
        static_assert(is_lvalue_reference_v<U>, "U must be an lvalue");
    }

    template <typename U>
        requires(not is_same_v<remove_cvref_t<U>, optional>)
    constexpr explicit(not is_convertible_v<U, T>) optional(optional<U> const& rhs)
        : _ptr(etl::addressof(*rhs))
    {
    }

    constexpr optional(optional const& other)     = default;
    constexpr optional(optional&& other) noexcept = default;
    constexpr ~optional()                         = default;

    constexpr auto operator=(optional const&) noexcept -> optional& = default;
    constexpr auto operator=(optional&&) noexcept -> optional&      = default;

    constexpr auto operator=(nullopt_t /*tag*/) noexcept -> optional&
    {
        _ptr = nullptr;
        return *this;
    }

    template <typename U = T>
        requires(not is_same_v<remove_cvref_t<U>, optional> and not conjunction_v<is_scalar<T>, is_same<T, decay_t<U>>>)
    constexpr auto operator=(U&& v) -> optional&
    {
        static_assert(is_constructible_v<add_lvalue_reference_t<T>, U>, "Must be able to bind U to T&");
        static_assert(is_lvalue_reference_v<U>, "U must be an lvalue");
        _ptr = etl::addressof(v);
        return *this;
    }

    template <typename U>
    constexpr auto operator=(optional<U> const& rhs) -> optional&
    {
        static_assert(is_constructible_v<add_lvalue_reference_t<T>, U>, "Must be able to bind U to T&");
        _ptr = rhs._ptr;
        return *this;
    }

    template <typename U = T>
        requires(not is_same_v<remove_cvref_t<U>, optional>)
    constexpr auto emplace(U&& u) noexcept -> optional&
    {
        *this = etl::forward<U>(u);
        return *this;
    }

    [[nodiscard]] constexpr auto operator->() const noexcept -> T* { return _ptr; }

    [[nodiscard]] constexpr auto operator*() const noexcept -> T& { return *_ptr; }

    [[nodiscard]] constexpr explicit operator bool() const noexcept { return has_value(); }

    [[nodiscard]] constexpr auto has_value() const noexcept -> bool { return _ptr != nullptr; }

    constexpr void reset() noexcept { _ptr = nullptr; }

    constexpr void swap(optional& rhs) noexcept { etl::swap(_ptr, rhs._ptr); }

private:
    T* _ptr{nullptr};
};

// One deduction guide is provided for etl::optional to account for the
// edge cases missed by the implicit deduction guides, in particular,
// non-copyable arguments and array to pointer conversion.
/// \relates optional
/// \ingroup optional
template <typename T>
optional(T) -> optional<T>;

/// \brief Compares two optional objects, lhs and rhs.
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator==(optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (static_cast<bool>(lhs) != static_cast<bool>(rhs)) {
        return false;
    }
    if (not static_cast<bool>(lhs) and not static_cast<bool>(rhs)) {
        return true;
    }
    return (*lhs) == (*rhs);
}

/// \brief Compares two optional objects, lhs and rhs.
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator!=(optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (static_cast<bool>(lhs) != static_cast<bool>(rhs)) {
        return true;
    }
    if (not static_cast<bool>(lhs) and not static_cast<bool>(rhs)) {
        return false;
    }
    return (*lhs) != (*rhs);
}

/// \brief Compares two optional objects, lhs and rhs.
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<(optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (not static_cast<bool>(rhs)) {
        return false;
    }
    if (not static_cast<bool>(lhs)) {
        return true;
    }
    return (*lhs) < (*rhs);
}

/// \brief Compares two optional objects, lhs and rhs.
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>(optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (not static_cast<bool>(lhs)) {
        return false;
    }
    if (not static_cast<bool>(rhs)) {
        return true;
    }
    return (*lhs) > (*rhs);
}

/// \brief Compares two optional objects, lhs and rhs.
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<=(optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (not static_cast<bool>(lhs)) {
        return true;
    }
    if (not static_cast<bool>(rhs)) {
        return false;
    }
    return (*lhs) <= (*rhs);
}

/// \brief Compares two optional objects, lhs and rhs.
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>=(optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (not static_cast<bool>(rhs)) {
        return true;
    }
    if (not static_cast<bool>(lhs)) {
        return false;
    }
    return (*lhs) >= (*rhs);
}

/// Compares opt with a nullopt.
///
/// Equivalent to when comparing to an optional that does not contain a value.
///
/// \relates optional
/// \ingroup optional
template <typename T>
[[nodiscard]] constexpr auto operator==(optional<T> const& opt, etl::nullopt_t /*unused*/) noexcept -> bool
{
    return not opt;
}

/// Compares opt with a nullopt.
///
/// Equivalent to when comparing to an optional that does not contain a value.
///
/// \relates optional
/// \ingroup optional
template <typename T>
[[nodiscard]] constexpr auto operator==(etl::nullopt_t /*unused*/, optional<T> const& opt) noexcept -> bool
{
    return not opt;
}

/// Compares opt with a nullopt.
///
/// Equivalent to when comparing to an optional that does not contain a value.
///
/// \relates optional
/// \ingroup optional
template <typename T>
[[nodiscard]] constexpr auto operator<(optional<T> const& /*opt*/, etl::nullopt_t /*unused*/) noexcept -> bool
{
    return false;
}

/// Compares opt with a nullopt.
///
/// Equivalent to when comparing to an optional that does not contain a value.
///
/// \relates optional
/// \ingroup optional
template <typename T>
[[nodiscard]] constexpr auto operator<(etl::nullopt_t /*unused*/, optional<T> const& opt) noexcept -> bool
{
    return static_cast<bool>(opt);
}

/// \brief Compares opt with a value. The values are compared (using the
/// corresponding operator of T) only if opt contains a value. Otherwise, opt is
/// considered less than value. If the corresponding two-way comparison
/// expression between *opt and value is not well-formed, or if its result is
/// not convertible to bool, the program is ill-formed.
///
/// https://en.cppreference.com/w/cpp/utility/optional/operator_cmp
///
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator==(optional<T> const& opt, U const& value) -> bool
{
    return static_cast<bool>(opt) ? *opt == value : false;
}

/// \brief Compares opt with a value. The values are compared (using the
/// corresponding operator of T) only if opt contains a value. Otherwise, opt is
/// considered less than value. If the corresponding two-way comparison
/// expression between *opt and value is not well-formed, or if its result is
/// not convertible to bool, the program is ill-formed.
///
/// https://en.cppreference.com/w/cpp/utility/optional/operator_cmp
///
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator==(T const& value, optional<U> const& opt) -> bool
{
    return static_cast<bool>(opt) ? value == *opt : false;
}

/// \brief Compares opt with a value. The values are compared (using the
/// corresponding operator of T) only if opt contains a value. Otherwise, opt is
/// considered less than value. If the corresponding two-way comparison
/// expression between *opt and value is not well-formed, or if its result is
/// not convertible to bool, the program is ill-formed.
///
/// https://en.cppreference.com/w/cpp/utility/optional/operator_cmp
///
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator!=(optional<T> const& opt, U const& value) -> bool
{
    return static_cast<bool>(opt) ? *opt != value : true;
}

/// \brief Compares opt with a value. The values are compared (using the
/// corresponding operator of T) only if opt contains a value. Otherwise, opt is
/// considered less than value. If the corresponding two-way comparison
/// expression between *opt and value is not well-formed, or if its result is
/// not convertible to bool, the program is ill-formed.
///
/// https://en.cppreference.com/w/cpp/utility/optional/operator_cmp
///
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator!=(T const& value, optional<U> const& opt) -> bool
{
    return static_cast<bool>(opt) ? value != *opt : true;
}

/// \brief Compares opt with a value. The values are compared (using the
/// corresponding operator of T) only if opt contains a value. Otherwise, opt is
/// considered less than value. If the corresponding two-way comparison
/// expression between *opt and value is not well-formed, or if its result is
/// not convertible to bool, the program is ill-formed.
///
/// https://en.cppreference.com/w/cpp/utility/optional/operator_cmp
///
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<(optional<T> const& opt, U const& value) -> bool
{
    return static_cast<bool>(opt) ? *opt < value : true;
}

/// \brief Compares opt with a value. The values are compared (using the
/// corresponding operator of T) only if opt contains a value. Otherwise, opt is
/// considered less than value. If the corresponding two-way comparison
/// expression between *opt and value is not well-formed, or if its result is
/// not convertible to bool, the program is ill-formed.
///
/// https://en.cppreference.com/w/cpp/utility/optional/operator_cmp
///
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<(T const& value, optional<U> const& opt) -> bool
{
    return static_cast<bool>(opt) ? value < *opt : false;
}

/// \brief Compares opt with a value. The values are compared (using the
/// corresponding operator of T) only if opt contains a value. Otherwise, opt is
/// considered less than value. If the corresponding two-way comparison
/// expression between *opt and value is not well-formed, or if its result is
/// not convertible to bool, the program is ill-formed.
///
/// https://en.cppreference.com/w/cpp/utility/optional/operator_cmp
///
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>(optional<T> const& opt, U const& value) -> bool
{
    return static_cast<bool>(opt) ? *opt > value : false;
}

/// \brief Compares opt with a value. The values are compared (using the
/// corresponding operator of T) only if opt contains a value. Otherwise, opt is
/// considered less than value. If the corresponding two-way comparison
/// expression between *opt and value is not well-formed, or if its result is
/// not convertible to bool, the program is ill-formed.
///
/// https://en.cppreference.com/w/cpp/utility/optional/operator_cmp
///
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>(T const& value, optional<U> const& opt) -> bool
{
    return static_cast<bool>(opt) ? value > *opt : true;
}

/// \brief Compares opt with a value. The values are compared (using the
/// corresponding operator of T) only if opt contains a value. Otherwise, opt is
/// considered less than value. If the corresponding two-way comparison
/// expression between *opt and value is not well-formed, or if its result is
/// not convertible to bool, the program is ill-formed.
///
/// https://en.cppreference.com/w/cpp/utility/optional/operator_cmp
///
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<=(optional<T> const& opt, U const& value) -> bool
{
    return static_cast<bool>(opt) ? *opt <= value : true;
}

/// \brief Compares opt with a value. The values are compared (using the
/// corresponding operator of T) only if opt contains a value. Otherwise, opt is
/// considered less than value. If the corresponding two-way comparison
/// expression between *opt and value is not well-formed, or if its result is
/// not convertible to bool, the program is ill-formed.
///
/// https://en.cppreference.com/w/cpp/utility/optional/operator_cmp
///
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<=(T const& value, optional<U> const& opt) -> bool
{
    return static_cast<bool>(opt) ? value <= *opt : false;
}

/// \brief Compares opt with a value. The values are compared (using the
/// corresponding operator of T) only if opt contains a value. Otherwise, opt is
/// considered less than value. If the corresponding two-way comparison
/// expression between *opt and value is not well-formed, or if its result is
/// not convertible to bool, the program is ill-formed.
///
/// https://en.cppreference.com/w/cpp/utility/optional/operator_cmp
///
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>=(optional<T> const& opt, U const& value) -> bool
{
    return static_cast<bool>(opt) ? *opt >= value : false;
}

/// \brief Compares opt with a value. The values are compared (using the
/// corresponding operator of T) only if opt contains a value. Otherwise, opt is
/// considered less than value. If the corresponding two-way comparison
/// expression between *opt and value is not well-formed, or if its result is
/// not convertible to bool, the program is ill-formed.
///
/// https://en.cppreference.com/w/cpp/utility/optional/operator_cmp
///
/// \relates optional
/// \ingroup optional
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>=(T const& value, optional<U> const& opt) -> bool
{
    return static_cast<bool>(opt) ? value >= *opt : true;
}

/// \brief The template specialization of etl::hash for the etl::optional class
/// allows users to obtain hashes of the values contained in optional objects.
///
/// The specialization etl::hash<optional<T>> is enabled (see etl::hash)
/// if etl::hash<etl::remove_const_t<T>> is enabled, and is disabled otherwise.
///
/// When enabled, for an object opt of type etl::optional<T> that contains a
/// value, etl::hash<etl::optional<T>>()(opt) evaluates to the same value as
/// etl::hash<etl::remove_const_t<T>>()(*opt). For an optional that does not
/// contain a value, the hash is unspecified.
///
/// The member functions of this specialization are not guaranteed to be
/// noexcept because the hash of the underlying type might throw.
///
/// https://en.cppreference.com/w/cpp/utility/optional/hash
///
/// \headerfile etl/optional.hpp
/// \ingroup optional
template <typename T>
struct hash<etl::optional<T>> {
    [[nodiscard]] constexpr auto operator()(etl::optional<T> const& opt) const -> etl::size_t
    {
        using type = etl::remove_const_t<T>;
        static_assert(etl::is_specialized_v<etl::hash, type>);
        return static_cast<bool>(opt) ? etl::hash<type>{}(*opt) : 0;
    }
};
} // namespace etl

#endif // TETL_OPTIONAL_OPTIONAL_HPP
