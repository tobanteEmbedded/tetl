/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_OPTIONAL_OPTIONAL_HPP
#define TETL_OPTIONAL_OPTIONAL_HPP

#include "etl/_concepts/requires.hpp"
#include "etl/_config/all.hpp"
#include "etl/_exception/raise.hpp"
#include "etl/_functional/hash.hpp"
#include "etl/_memory/addressof.hpp"
#include "etl/_new/operator.hpp"
#include "etl/_optional/bad_optional_access.hpp"
#include "etl/_optional/nullopt.hpp"
#include "etl/_optional/sfinae_base.hpp"
#include "etl/_type_traits/conjunction.hpp"
#include "etl/_type_traits/decay.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/is_assignable.hpp"
#include "etl/_type_traits/is_constructible.hpp"
#include "etl/_type_traits/is_convertible.hpp"
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
#include "etl/_type_traits/is_scalar.hpp"
#include "etl/_type_traits/is_specialized.hpp"
#include "etl/_type_traits/is_swappable.hpp"
#include "etl/_type_traits/is_trivially_copy_assignable.hpp"
#include "etl/_type_traits/is_trivially_copy_constructible.hpp"
#include "etl/_type_traits/is_trivially_destructible.hpp"
#include "etl/_type_traits/is_trivially_move_assignable.hpp"
#include "etl/_type_traits/is_trivially_move_constructible.hpp"
#include "etl/_type_traits/negation.hpp"
#include "etl/_type_traits/remove_const.hpp"
#include "etl/_type_traits/remove_cvref.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/in_place.hpp"
#include "etl/_utility/move.hpp"
#include "etl/_utility/swap.hpp"

namespace etl {

namespace detail {
template <typename T, bool = etl::is_trivially_destructible_v<T>>
struct optional_destruct_base;

template <typename T>
struct optional_destruct_base<T, false> {
    using value_type = T;
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

    auto reset() noexcept -> void
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

template <typename T>
struct optional_destruct_base<T, true> {
    using value_type = T;
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

template <typename T, bool = etl::is_reference_v<T>>
struct optional_storage_base : optional_destruct_base<T> {
    using base_t     = optional_destruct_base<T>;
    using value_type = T;
    using base_t::base_t;

    [[nodiscard]] constexpr auto has_value() const noexcept -> bool
    {
        return this->internal_has_value;
    }

    [[nodiscard]] constexpr auto get() & noexcept -> value_type&
    {
        return this->internal_value;
    }

    [[nodiscard]] constexpr auto get() const& noexcept -> value_type const&
    {
        return this->internal_value;
    }

    [[nodiscard]] constexpr auto get() && noexcept -> value_type&&
    {
        return etl::move(this->internal_value);
    }

    [[nodiscard]] constexpr auto get() const&& noexcept -> value_type const&&
    {
        return etl::move(this->internal_value);
    }

    template <typename... Args>

    void construct(Args&&... args)
    {
        ::new (static_cast<void*>(etl::addressof(this->internal_value)))
            value_type(etl::forward<Args>(args)...);
        this->internal_has_value = true;
    }

    template <typename U>
    void construct_from(U&& opt)
    {
        if (opt.has_value()) { construct(etl::forward<U>(opt).get()); }
    }

    template <typename U>
    void assign_from(U&& opt)
    {
        if (this->internal_has_value == opt.has_value()) {
            if (this->internal_has_value) {
                this->internal_value = etl::forward<U>(opt).get();
            }
        } else {
            if (this->internal_has_value) {
                this->reset();
            } else {
                construct(etl::forward<U>(opt).get());
            }
        }
    }
};

template <typename T, bool = etl::is_trivially_copy_constructible_v<T>>
struct optional_copy_base : optional_storage_base<T> {
    using optional_storage_base<T>::optional_storage_base;
};

template <typename T>
struct optional_copy_base<T, false> : optional_storage_base<T> {
    using optional_storage_base<T>::optional_storage_base;

    optional_copy_base() = default;

    optional_copy_base(optional_copy_base const& opt)
        : optional_storage_base<T>::optional_storage_base {}
    {
        this->construct_from(opt);
    }

    optional_copy_base(optional_copy_base&&) noexcept = default;

    auto operator=(optional_copy_base const&) -> optional_copy_base& = default;
    auto operator              =(optional_copy_base&&) noexcept
        -> optional_copy_base& = default;
};

template <typename T, bool = etl::is_trivially_move_constructible_v<T>>
struct optional_move_base : optional_copy_base<T> {
    using optional_copy_base<T>::optional_copy_base;
};

template <typename T>
struct optional_move_base<T, false> : optional_copy_base<T> {
    using value_type = T;
    using optional_copy_base<T>::optional_copy_base;

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

template <typename T, bool = etl::is_trivially_destructible_v<T>&&
                          etl::is_trivially_copy_constructible_v<T>&&
                              etl::is_trivially_copy_assignable_v<T>>
struct optional_copy_assign_base : optional_move_base<T> {
    using optional_move_base<T>::optional_move_base;
};

template <typename T>
struct optional_copy_assign_base<T, false> : optional_move_base<T> {
    using optional_move_base<T>::optional_move_base;

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

template <typename T, bool = etl::is_trivially_destructible_v<T>&&
                          etl::is_trivially_move_constructible_v<T>&&
                              etl::is_trivially_move_assignable_v<T>>
struct optional_move_assign_base : optional_copy_assign_base<T> {
    using optional_copy_assign_base<T>::optional_copy_assign_base;
};

template <typename T>
struct optional_move_assign_base<T, false> : optional_copy_assign_base<T> {
    using value_type = T;
    using optional_copy_assign_base<T>::optional_copy_assign_base;

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

template <typename T>
using optional_sfinae_ctor_base_t
    = sfinae_ctor_base<etl::is_copy_constructible_v<T>,
        etl::is_move_constructible_v<T>>;

template <typename T>
using optional_sfinae_assign_base_t = sfinae_assign_base<
    (etl::is_copy_constructible_v<T> && etl::is_copy_assignable_v<T>),
    (etl::is_move_constructible_v<T> && etl::is_move_assignable_v<T>)>;

} // namespace detail

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
/// \headerfile optional.hpp "etl/optional.hpp"
/// \include optional.cpp
template <typename T>
struct optional : private detail::optional_move_assign_base<T>,
                  private detail::optional_sfinae_ctor_base_t<T>,
                  private detail::optional_sfinae_assign_base_t<T> {
private:
    using base_type = detail::optional_move_assign_base<T>;

    // clang-format off
    static_assert(!is_same_v<remove_cvref_t<T>, in_place_t>, "instantiation of optional with in_place_t is ill-formed");
    static_assert(!is_same_v<remove_cvref_t<T>, nullopt_t>, "instantiation of optional with nullopt_t is ill-formed");
    static_assert(!is_reference_v<T>, "instantiation of optional with a reference type is ill-formed");
    static_assert(!is_array_v<T>, "instantiation of optional with an array type is ill-formed");

    template<typename U>
    static constexpr bool not_in_place_t = !etl::is_same_v<etl::remove_cvref_t<U>, etl::in_place_t>;
    template<typename U>
    static constexpr bool not_self = !etl::is_same_v<etl::remove_cvref_t<U>, etl::optional<T>>;

    template<typename U>
    static constexpr bool enable_ctor_4_5_base =
            (!etl::is_constructible_v<T, etl::optional<U>&>)
        &&  (!etl::is_constructible_v<T, etl::optional<U> const&>)
        &&  (!etl::is_constructible_v<T, etl::optional<U>&&>)
        &&  (!etl::is_constructible_v<T, etl::optional<U> const&&>)
        &&  (!etl::is_convertible_v<etl::optional<U>&, T>)
        &&  (!etl::is_convertible_v<etl::optional<U> const&, T>)
        &&  (!etl::is_convertible_v<etl::optional<U>&&, T>)
        &&  (!etl::is_convertible_v<etl::optional<U> const&&, T>);

    template<typename U>
    using enable_ctor_4_implicit = etl::enable_if_t<
        etl::is_constructible_v<T, U const&>
        && enable_ctor_4_5_base<U>
        && etl::is_convertible_v<U const&, T>, int>;

    template<typename U>
    using enable_ctor_4_explicit = etl::enable_if_t<
        etl::is_constructible_v<T, U const&>
        && enable_ctor_4_5_base<U>
        && (!etl::is_convertible_v<U const&, T>), int>;

    template<typename U>
    using enable_ctor_5_implicit = etl::enable_if_t<
        etl::is_constructible_v<T, U&&>
        && enable_ctor_4_5_base<U>
        && etl::is_convertible_v<U&&, T>, int>;

    template<typename U>
    using enable_ctor_5_explicit = etl::enable_if_t<
        etl::is_constructible_v<T, U&&>
        && enable_ctor_4_5_base<U>
        && (!etl::is_convertible_v<U&&, T>), int>;


    template<typename ...Args>
    using enable_ctor_6 = etl::enable_if_t<etl::is_constructible_v<T, Args...>, int>;

    template<typename U>
    static constexpr bool enable_ctor_8 = etl::is_constructible_v<T, U&&> && not_in_place_t<U> && not_self<U>;
    template<typename U>
    using enable_ctor_8_implicit = etl::enable_if_t<enable_ctor_8<U> && etl::is_convertible_v<U&&, T>, int>;
    template<typename U>
    using enable_ctor_8_explicit = etl::enable_if_t<enable_ctor_8<U> && (!etl::is_convertible_v<U&&, T>), int>;

    template <typename U>
    using enable_assign_forward = etl::enable_if_t<
            (!etl::is_same_v<optional<T>, etl::decay_t<U>>)
        &&  (!etl::is_scalar_v<T>)
        &&  (!etl::is_same_v<T, etl::decay_t<U>>)
        &&    etl::is_constructible_v<T, U>
        &&    etl::is_assignable_v<T&, U>, int>;

    template <typename U>
    static constexpr bool enable_assign_other =
            etl::is_constructible_v<T, etl::optional<U>&>
        &&  etl::is_constructible_v<T, etl::optional<U> const&>
        &&  etl::is_constructible_v<T, etl::optional<U>&&>
        &&  etl::is_constructible_v<T, etl::optional<U> const&&>
        &&  etl::is_convertible_v<etl::optional<U>&, T>
        &&  etl::is_convertible_v<etl::optional<U> const&, T>
        &&  etl::is_convertible_v<etl::optional<U>&&, T>
        &&  etl::is_convertible_v<etl::optional<U> const&&, T>
        &&  etl::is_assignable_v<T&, etl::optional<U>&>
        &&  etl::is_assignable_v<T&, etl::optional<U> const&>
        &&  etl::is_assignable_v<T&, etl::optional<U>&&>
        &&  etl::is_assignable_v<T&, etl::optional<U> const&&>;

    template <typename U>
    using enable_assign_other_copy = etl::enable_if_t<
            enable_assign_other<U>
        &&  etl::is_constructible_v<T, U const&>
        &&  etl::is_assignable_v<T&, U const&>, int>;

    template <typename U>
    using enable_assign_other_move = etl::enable_if_t<
            enable_assign_other<U>
        &&  etl::is_constructible_v<T, U>
        &&  etl::is_assignable_v<T&, U>, int>;

    // clang-format on

public:
    using value_type = T;

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

    /// \brief (4) Converting copy constructor: If other doesn't contain a
    /// value, constructs an optional object that does not contain a value.
    /// Otherwise, constructs an optional object that contains a value,
    /// initialized as if direct-initializing (but not direct-list-initializing)
    /// an object of type T with the expression *other.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/optional
    template <typename U, enable_ctor_4_implicit<U> = 0>
    constexpr optional(optional<U> const& other)
    {
        if (other.has_value()) { this->construct(*other); }
    }

    /// \brief (4) Converting copy constructor: If other doesn't contain a
    /// value, constructs an optional object that does not contain a value.
    /// Otherwise, constructs an optional object that contains a value,
    /// initialized as if direct-initializing (but not direct-list-initializing)
    /// an object of type T with the expression *other.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/optional
    template <typename U, enable_ctor_4_explicit<U> = 0>
    explicit constexpr optional(optional<U> const& other)
    {
        if (other.has_value()) { this->construct(*other); }
    }

    /// \brief (5) Converting move constructor: If other doesn't contain a
    /// value, constructs an optional object that does not contain a value.
    /// Otherwise, constructs an optional object that contains a value,
    /// initialized as if direct-initializing (but not direct-list-initializing)
    /// an object of type T with the expression etl::move(*other).
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/optional
    template <typename U, enable_ctor_5_implicit<U> = 0>
    constexpr optional(optional<U>&& other)
    {
        if (other.has_value()) { this->construct(*etl::move(other)); }
    }

    /// \brief (5) Converting move constructor: If other doesn't contain a
    /// value, constructs an optional object that does not contain a value.
    /// Otherwise, constructs an optional object that contains a value,
    /// initialized as if direct-initializing (but not direct-list-initializing)
    /// an object of type T with the expression etl::move(*other).
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/optional
    template <typename U, enable_ctor_5_explicit<U> = 0>
    explicit constexpr optional(optional<U>&& other)
    {
        if (other.has_value()) { this->construct(*etl::move(other)); }
    }

    /// \brief (6) Constructs an optional object that contains a value,
    /// initialized as if direct-initializing.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/optional
    template <typename... Args, enable_ctor_6<Args...> = 0>
    constexpr explicit optional(in_place_t /*unused*/, Args&&... arguments)
        : base_type(in_place, forward<Args>(arguments)...)
    {
    }

    /// \brief (8) Constructs an optional object that contains a value,
    /// initialized as if direct-initializing.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/optional
    template <typename U = T, enable_ctor_8_implicit<U> = 0>
    constexpr optional(U&& value) : base_type(in_place, forward<U>(value))
    {
    }

    /// \brief (8) Constructs an optional object that contains a value,
    /// initialized as if direct-initializing.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/optional
    template <typename U = T, enable_ctor_8_explicit<U> = 0>
    explicit constexpr optional(U&& value)
        : base_type(in_place, forward<U>(value))
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
    constexpr auto operator=(optional const& other) -> optional& = default;

    /// \brief Assigns the state of other.
    constexpr auto operator=(optional&& other) noexcept -> optional& = default;

    /// \brief Perfect-forwarded assignment.
    ///
    /// \details Depending on whether *this contains a value before the call,
    /// the contained value is either direct-initialized from
    /// etl::forward<U>(value) or assigned from etl::forward<U>(value).
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/operator%3D
    template <typename U = T, enable_assign_forward<U> = 0>
    constexpr auto operator=(U&& value) -> optional&
    {
        if (this->has_value()) {
            this->get() = etl::forward<U>(value);
            return *this;
        }

        this->construct(etl::forward<U>(value));
        return *this;
    }

    /// \brief Assigns the state of other.
    template <typename U = T, enable_assign_other_copy<U> = 0>
    constexpr auto operator=(optional<U> const& other) -> optional&
    {
        if (this->has_value()) {
            if (other.has_value()) {
                this->get() = *other;
                return *this;
            }
            this->reset();
        }

        if (other.has_value()) { this->construct(*other); }
        return *this;
    }

    /// \brief Assigns the state of other.
    template <typename U = T, enable_assign_other_move<U> = 0>
    constexpr auto operator=(optional<U>&& other) -> optional&
    {
        if (this->has_value()) {
            if (other.has_value()) {
                this->get() = etl::move(*other);
                return *this;
            }
            this->reset();
        }

        if (other.has_value()) { this->construct(etl::move(*other)); }
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

    /// \brief If *this contains a value, returns a reference to the contained
    /// value. Otherwise, raises a etl::bad_optional_access exception.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/value
    [[nodiscard]] constexpr auto value() & -> value_type&
    {
        if (TETL_LIKELY(has_value())) { return this->get(); }
        etl::raise<etl::bad_optional_access>(
            "called value() on empty optional");
    }

    /// \brief If *this contains a value, returns a reference to the contained
    /// value. Otherwise, raises a etl::bad_optional_access exception.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/value
    [[nodiscard]] constexpr auto value() const& -> value_type const&
    {
        if (TETL_LIKELY(has_value())) { return this->get(); }
        etl::raise<etl::bad_optional_access>(
            "called value() on empty optional");
    }

    /// \brief If *this contains a value, returns a reference to the contained
    /// value. Otherwise, raises a etl::bad_optional_access exception.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/value
    [[nodiscard]] constexpr auto value() && -> value_type&&
    {
        if (TETL_LIKELY(has_value())) { return etl::move(this->get()); }
        etl::raise<etl::bad_optional_access>(
            "called value() on empty optional");
    }

    /// \brief If *this contains a value, returns a reference to the contained
    /// value. Otherwise, raises a etl::bad_optional_access exception.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/value
    [[nodiscard]] constexpr auto value() const&& -> value_type const&&
    {
        if (TETL_LIKELY(has_value())) { return etl::move(this->get()); }
        etl::raise<etl::bad_optional_access>(
            "called value() on empty optional");
    }

    /// \brief Returns the contained value if *this has a value, otherwise
    /// returns default_value.
    template <typename U>
    [[nodiscard]] constexpr auto value_or(U&& defaultValue) const& -> value_type
    {
        return has_value()
                   ? this->value()
                   : static_cast<value_type>(etl::forward<U>(defaultValue));
    }

    /// \brief Returns the contained value if *this has a value, otherwise
    /// returns default_value.
    template <typename U>
    [[nodiscard]] constexpr auto value_or(U&& defaultValue) && -> value_type
    {
        return has_value()
                   ? etl::move(this->value())
                   : static_cast<value_type>(etl::forward<U>(defaultValue));
    }

    /// \brief Returns a pointer to the contained value. The pointer is null if
    /// the optional is empty.
    [[nodiscard]] constexpr auto operator->() const -> value_type const*
    {
        if (has_value()) { return &this->value(); }
        return nullptr;
    }

    /// \brief Returns a pointer to the contained value. The pointer is null if
    /// the optional is empty.
    [[nodiscard]] constexpr auto operator->() -> value_type*
    {
        if (has_value()) { return &this->value(); }
        return nullptr;
    }

    /// \brief Returns a reference to the contained value.
    ///
    /// \details This operator only checks whether the optional contains a
    /// value in debug builds! You can do so manually by using has_value() or
    /// simply operator bool(). Alternatively, if checked access is needed,
    /// value() or value_or() may be used.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/operator*
    [[nodiscard]] constexpr auto operator*() const& -> T const&
    {
        TETL_ASSERT(has_value());
        return this->get();
    }

    /// \brief Returns a reference to the contained value.
    ///
    /// \details This operator only checks whether the optional contains a
    /// value in debug builds! You can do so manually by using has_value() or
    /// simply operator bool(). Alternatively, if checked access is needed,
    /// value() or value_or() may be used.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/operator*
    [[nodiscard]] constexpr auto operator*() & -> T&
    {
        TETL_ASSERT(has_value());
        return this->get();
    }

    /// \brief Returns a reference to the contained value.
    ///
    /// \details This operator only checks whether the optional contains a
    /// value in debug builds! You can do so manually by using has_value() or
    /// simply operator bool(). Alternatively, if checked access is needed,
    /// value() or value_or() may be used.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/operator*
    [[nodiscard]] constexpr auto operator*() const&& -> T const&&
    {
        TETL_ASSERT(has_value());
        return etl::move(this->get());
    }

    /// \brief Returns a reference to the contained value.
    ///
    /// \details This operator only checks whether the optional contains a
    /// value in debug builds! You can do so manually by using has_value() or
    /// simply operator bool(). Alternatively, if checked access is needed,
    /// value() or value_or() may be used.
    ///
    /// https://en.cppreference.com/w/cpp/utility/optional/operator*
    [[nodiscard]] constexpr auto operator*() && -> T&&
    {
        TETL_ASSERT(has_value());
        return etl::move(this->get());
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
        return value();
    }

    /// \brief Implementation detail. Do not use!
    using base_type::get;
};

// One deduction guide is provided for etl::optional to account for the
// edge cases missed by the implicit deduction guides, in particular,
// non-copyable arguments and array to pointer conversion.
template <typename T>
optional(T) -> optional<T>;

/// \brief Overloads the etl::swap algorithm for etl::optional. Exchanges the
/// state of lhs with that of rhs. Effectively calls lhs.swap(rhs).
///
/// https://en.cppreference.com/w/cpp/utility/optional/swap2
template <typename T>
constexpr auto swap(etl::optional<T>& lhs, etl::optional<T>& rhs) noexcept(
    noexcept(lhs.swap(rhs)))
    -> etl::enable_if_t<
        etl::is_move_constructible_v<T> && etl::is_swappable_v<T>>
{
    lhs.swap(rhs);
}

/// \brief Compares two optional objects, lhs and rhs.
template <typename T, typename U>
[[nodiscard]] constexpr auto operator==(
    optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (static_cast<bool>(lhs) != static_cast<bool>(rhs)) { return false; }
    if (!static_cast<bool>(lhs) && !static_cast<bool>(rhs)) { return true; }
    return lhs.value() == rhs.value();
}

/// \brief Compares two optional objects, lhs and rhs.
template <typename T, typename U>
[[nodiscard]] constexpr auto operator!=(
    optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (static_cast<bool>(lhs) != static_cast<bool>(rhs)) { return true; }
    if (!static_cast<bool>(lhs) && !static_cast<bool>(rhs)) { return false; }
    return lhs.value() != rhs.value();
}

/// \brief Compares two optional objects, lhs and rhs.
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<(
    optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (!static_cast<bool>(rhs)) { return false; }
    if (!static_cast<bool>(lhs)) { return true; }
    return lhs.value() < rhs.value();
}

/// \brief Compares two optional objects, lhs and rhs.
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>(
    optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (!static_cast<bool>(lhs)) { return false; }
    if (!static_cast<bool>(rhs)) { return true; }
    return lhs.value() > rhs.value();
}

/// \brief Compares two optional objects, lhs and rhs.
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<=(
    optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (!static_cast<bool>(lhs)) { return true; }
    if (!static_cast<bool>(rhs)) { return false; }
    return lhs.value() <= rhs.value();
}

/// \brief Compares two optional objects, lhs and rhs.
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>=(
    optional<T> const& lhs, optional<U> const& rhs) -> bool
{
    if (!static_cast<bool>(rhs)) { return true; }
    if (!static_cast<bool>(lhs)) { return false; }
    return lhs.value() >= rhs.value();
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

/// \brief Compares opt with a value. The values are compared (using the
/// corresponding operator of T) only if opt contains a value. Otherwise, opt is
/// considered less than value. If the corresponding two-way comparison
/// expression between *opt and value is not well-formed, or if its result is
/// not convertible to bool, the program is ill-formed.
///
/// https://en.cppreference.com/w/cpp/utility/optional/operator_cmp
template <typename T, typename U>
[[nodiscard]] constexpr auto operator==(optional<T> const& opt, U const& value)
    -> bool
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
template <typename T, typename U>
[[nodiscard]] constexpr auto operator==(T const& value, optional<U> const& opt)
    -> bool
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
template <typename T, typename U>
[[nodiscard]] constexpr auto operator!=(optional<T> const& opt, U const& value)
    -> bool
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
template <typename T, typename U>
[[nodiscard]] constexpr auto operator!=(T const& value, optional<U> const& opt)
    -> bool
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
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<(optional<T> const& opt, U const& value)
    -> bool
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
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<(T const& value, optional<U> const& opt)
    -> bool
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
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>(optional<T> const& opt, U const& value)
    -> bool
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
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>(T const& value, optional<U> const& opt)
    -> bool
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
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<=(optional<T> const& opt, U const& value)
    -> bool
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
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<=(T const& value, optional<U> const& opt)
    -> bool
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
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>=(optional<T> const& opt, U const& value)
    -> bool
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
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>=(T const& value, optional<U> const& opt)
    -> bool
{
    return static_cast<bool>(opt) ? value >= *opt : true;
}

/// \brief The template specialization of etl::hash for the etl::optional class
/// allows users to obtain hashes of the values contained in optional objects.
///
/// \details The specialization etl::hash<optional<T>> is enabled (see
/// etl::hash) if etl::hash<etl::remove_const_t<T>> is enabled, and is disabled
/// otherwise.
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
/// \headerfile optional.hpp "etl/optional.hpp"
template <typename T>
struct hash<etl::optional<T>> {
    [[nodiscard]] constexpr auto operator()(etl::optional<T> const& opt) const
        -> etl::size_t
    {
        using type = etl::remove_const_t<T>;
        static_assert(etl::is_specialized_v<etl::hash, type>);
        return static_cast<bool>(opt) ? etl::hash<type> {}(*opt) : 0;
    }
};
} // namespace etl

#endif // TETL_OPTIONAL_OPTIONAL_HPP