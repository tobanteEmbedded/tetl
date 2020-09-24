/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_OPTIONAL_HPP
#define TAETL_OPTIONAL_HPP

#include "etl/cassert.hpp"
#include "etl/memory.hpp"
#include "etl/type_traits.hpp"
#include "etl/utility.hpp"

namespace etl
{
/**
 * @brief etl::nullopt_t is an empty class type used to indicate optional type
 * with uninitialized state. In particular, etl::optional has a constructor with
 * nullopt_t as a single argument, which creates an optional that does not
 * contain a value.
 */
struct nullopt_t
{
    explicit constexpr nullopt_t(int) { }
};

/**
 * @brief etl::nullopt is a constant of type etl::nullopt_t that is used to
 * indicate optional type with uninitialized state.
 */
inline constexpr auto nullopt = etl::nullopt_t {{}};

namespace detail
{
template <bool CanCopy, bool CanMove>
struct sfinae_ctor_base
{
};
template <>
struct sfinae_ctor_base<false, false>
{
    sfinae_ctor_base()                        = default;
    sfinae_ctor_base(sfinae_ctor_base const&) = delete;
    sfinae_ctor_base(sfinae_ctor_base&&)      = delete;
    sfinae_ctor_base& operator=(sfinae_ctor_base const&) = default;
    sfinae_ctor_base& operator=(sfinae_ctor_base&&) = default;
};
template <>
struct sfinae_ctor_base<true, false>
{
    sfinae_ctor_base()                        = default;
    sfinae_ctor_base(sfinae_ctor_base const&) = default;
    sfinae_ctor_base(sfinae_ctor_base&&)      = delete;
    sfinae_ctor_base& operator=(sfinae_ctor_base const&) = default;
    sfinae_ctor_base& operator=(sfinae_ctor_base&&) = default;
};
template <>
struct sfinae_ctor_base<false, true>
{
    sfinae_ctor_base()                        = default;
    sfinae_ctor_base(sfinae_ctor_base const&) = delete;
    sfinae_ctor_base(sfinae_ctor_base&&)      = default;
    sfinae_ctor_base& operator=(sfinae_ctor_base const&) = default;
    sfinae_ctor_base& operator=(sfinae_ctor_base&&) = default;
};

template <bool CanCopy, bool CanMove>
struct sfinae_assign_base
{
};
template <>
struct sfinae_assign_base<false, false>
{
    sfinae_assign_base()                          = default;
    sfinae_assign_base(sfinae_assign_base const&) = default;
    sfinae_assign_base(sfinae_assign_base&&)      = default;
    sfinae_assign_base& operator=(sfinae_assign_base const&) = delete;
    sfinae_assign_base& operator=(sfinae_assign_base&&) = delete;
};
template <>
struct sfinae_assign_base<true, false>
{
    sfinae_assign_base()                          = default;
    sfinae_assign_base(sfinae_assign_base const&) = default;
    sfinae_assign_base(sfinae_assign_base&&)      = default;
    sfinae_assign_base& operator=(sfinae_assign_base const&) = default;
    sfinae_assign_base& operator=(sfinae_assign_base&&) = delete;
};
template <>
struct sfinae_assign_base<false, true>
{
    sfinae_assign_base()                          = default;
    sfinae_assign_base(sfinae_assign_base const&) = default;
    sfinae_assign_base(sfinae_assign_base&&)      = default;
    sfinae_assign_base& operator=(sfinae_assign_base const&) = delete;
    sfinae_assign_base& operator=(sfinae_assign_base&&) = default;
};

template <class ValueType, bool = etl::is_trivially_destructible<ValueType>::value>
struct optional_destruct_base;

template <class ValueType>
struct optional_destruct_base<ValueType, false>
{
    using value_type = ValueType;
    static_assert(etl::is_object_v<value_type>, "undefined behavior");

    ~optional_destruct_base()
    {
        if (has_value_) value_.~value_type();
    }

    constexpr optional_destruct_base() noexcept : null_state_(), has_value_(false) { }

    template <class... Args>
    constexpr explicit optional_destruct_base(etl::in_place_t, Args&&... args)
        : value_(etl::forward<Args>(args)...), has_value_(true)
    {
    }

    void reset() noexcept
    {
        if (has_value_)
        {
            value_.~value_type();
            has_value_ = false;
        }
    }

    union
    {
        char null_state_;
        value_type value_;
    };
    bool has_value_;
};

template <class ValueType>
struct optional_destruct_base<ValueType, true>
{
    typedef ValueType value_type;
    static_assert(etl::is_object_v<value_type>, "undefined behavior");

    constexpr optional_destruct_base() noexcept : null_state_(), has_value_(false) { }

    template <class... Args>
    constexpr explicit optional_destruct_base(etl::in_place_t, Args&&... args)
        : value_(static_cast<ValueType>(etl::forward<Args>(args))...), has_value_(true)
    {
    }

    void reset() noexcept
    {
        if (has_value_) { has_value_ = false; }
    }

    union
    {
        char null_state_;
        value_type value_;
    };
    bool has_value_;
};

template <class ValueType, bool = etl::is_reference<ValueType>::value>
struct optional_storage_base : optional_destruct_base<ValueType>
{
    using base_t     = optional_destruct_base<ValueType>;
    using value_type = ValueType;
    using base_t::base_t;

    constexpr bool has_value() const noexcept { return this->has_value_; }

    constexpr value_type& get() & noexcept { return this->value_; }

    constexpr const value_type& get() const& noexcept { return this->value_; }

    constexpr value_type&& get() && noexcept { return etl::move(this->value_); }

    constexpr const value_type&& get() const&& noexcept
    {
        return etl::move(this->value_);
    }

    template <class... Args>

    void construct(Args&&... args)
    {
        ::new ((void*)etl::addressof(this->value_))
            value_type(etl::forward<Args>(args)...);
        this->has_value_ = true;
    }

    template <class T>
    void construct_from(T&& opt)
    {
        if (opt.has_value()) construct(etl::forward<T>(opt).get());
    }

    template <class T>

    void assign_from(T&& opt)
    {
        if (this->has_value_ == opt.has_value())
        {
            if (this->has_value_) this->value_ = etl::forward<T>(opt).get();
        }
        else
        {
            if (this->has_value_)
                this->reset();
            else
                construct(etl::forward<T>(opt).get());
        }
    }
};

template <class ValueType, bool = etl::is_trivially_copy_constructible<ValueType>::value>
struct optional_copy_base : optional_storage_base<ValueType>
{
    using optional_storage_base<ValueType>::optional_storage_base;
};

template <class ValueType>
struct optional_copy_base<ValueType, false> : optional_storage_base<ValueType>
{
    using optional_storage_base<ValueType>::optional_storage_base;

    optional_copy_base() = default;

    optional_copy_base(const optional_copy_base& opt) { this->construct_from(opt); }

    optional_copy_base(optional_copy_base&&) = default;

    optional_copy_base& operator=(const optional_copy_base&) = default;
    optional_copy_base& operator=(optional_copy_base&&) = default;
};

template <class ValueType, bool = etl::is_trivially_move_constructible<ValueType>::value>
struct optional_move_base : optional_copy_base<ValueType>
{
    using optional_copy_base<ValueType>::optional_copy_base;
};

template <class ValueType>
struct optional_move_base<ValueType, false> : optional_copy_base<ValueType>
{
    using value_type = ValueType;
    using optional_copy_base<ValueType>::optional_copy_base;

    optional_move_base() = default;

    optional_move_base(const optional_move_base&) = default;

    optional_move_base(optional_move_base&& opt) noexcept(
        etl::is_nothrow_move_constructible_v<value_type>)
    {
        this->construct_from(etl::move(opt));
    }

    optional_move_base& operator=(const optional_move_base&) = default;

    optional_move_base& operator=(optional_move_base&&) = default;
};

template <class ValueType, bool = etl::is_trivially_destructible<ValueType>::value&&
                               etl::is_trivially_copy_constructible<ValueType>::value&&
                                   etl::is_trivially_copy_assignable<ValueType>::value>
struct optional_copy_assign_base : optional_move_base<ValueType>
{
    using optional_move_base<ValueType>::optional_move_base;
};

template <class ValueType>
struct optional_copy_assign_base<ValueType, false> : optional_move_base<ValueType>
{
    using optional_move_base<ValueType>::optional_move_base;

    optional_copy_assign_base() = default;

    optional_copy_assign_base(const optional_copy_assign_base&) = default;

    optional_copy_assign_base(optional_copy_assign_base&&) = default;

    optional_copy_assign_base& operator=(const optional_copy_assign_base& opt)
    {
        this->assign_from(opt);
        return *this;
    }

    optional_copy_assign_base& operator=(optional_copy_assign_base&&) = default;
};

template <class ValueType, bool = etl::is_trivially_destructible<ValueType>::value&&
                               etl::is_trivially_move_constructible<ValueType>::value&&
                                   etl::is_trivially_move_assignable<ValueType>::value>
struct optional_move_assign_base : optional_copy_assign_base<ValueType>
{
    using optional_copy_assign_base<ValueType>::optional_copy_assign_base;
};

template <class ValueType>
struct optional_move_assign_base<ValueType, false> : optional_copy_assign_base<ValueType>
{
    using value_type = ValueType;
    using optional_copy_assign_base<ValueType>::optional_copy_assign_base;

    optional_move_assign_base() = default;

    optional_move_assign_base(const optional_move_assign_base& opt) = default;

    optional_move_assign_base(optional_move_assign_base&&) = default;

    optional_move_assign_base& operator=(const optional_move_assign_base&) = default;

    optional_move_assign_base& operator=(optional_move_assign_base&& opt) noexcept(
        etl::is_nothrow_move_assignable_v<value_type>&&
            etl::is_nothrow_move_constructible_v<value_type>)
    {
        this->assign_from(etl::move(opt));
        return *this;
    }
};

template <class ValueType>
using optional_sfinae_ctor_base_t
    = sfinae_ctor_base<etl::is_copy_constructible<ValueType>::value,
                       etl::is_move_constructible<ValueType>::value>;

template <class ValueType>
using optional_sfinae_assign_base_t
    = sfinae_assign_base<(etl::is_copy_constructible<ValueType>::value
                          && etl::is_copy_assignable<ValueType>::value),
                         (etl::is_move_constructible<ValueType>::value
                          && etl::is_move_assignable<ValueType>::value)>;

}  // namespace detail

template <class ValueType>
class optional : private detail::optional_move_assign_base<ValueType>,
                 private detail::optional_sfinae_ctor_base_t<ValueType>,
                 private detail::optional_sfinae_assign_base_t<ValueType>
{
    using base_type = detail::optional_move_assign_base<ValueType>;

    //   Disable the reference extension using this static assert.
    static_assert(!etl::is_same_v<etl::remove_cvref_t<ValueType>, etl::in_place_t>,
                  "instantiation of optional with in_place_t is ill-formed");
    static_assert(!etl::is_same_v<etl::remove_cvref_t<ValueType>, etl::nullopt_t>,
                  "instantiation of optional with nullopt_t is ill-formed");
    static_assert(!etl::is_reference_v<ValueType>,
                  "instantiation of optional with a reference type is ill-formed");
    // static_assert(etl::is_destructible_v<ValueType>,
    //               "instantiation of optional with a non-destructible type is
    //               ill-formed");
    static_assert(!etl::is_array_v<ValueType>,
                  "instantiation of optional with an array type is ill-formed");

public:
    using value_type = ValueType;

    /**
     * @brief Constructs an object that does not contain a value.
     */
    constexpr optional() noexcept { }

    /**
     * @brief Constructs an object that does not contain a value.
     */
    constexpr optional(etl::nullopt_t) noexcept { }

    /**
     * @brief Copy constructor.
     */
    constexpr optional(optional const&) = default;

    /**
     * @brief Move constructor.
     */
    constexpr optional(optional&&) = default;

    /**
     * @brief Constructs an optional object that contains a value, initialized as if
     * direct-initializing.
     */
    template <typename U = value_type,
              typename   = typename etl::enable_if_t<
                  conjunction_v<is_constructible<ValueType, U&&>,
                                negation<is_same<remove_cvref_t<U>, optional<ValueType>>>,
                                negation<is_same<remove_cvref_t<U>, etl::in_place_t>>>>>
    constexpr optional(U&& value) : base_type(etl::in_place, etl::forward<U>(value))
    {
    }

    /**
     * @brief If *this contains a value before the call, the contained value is
     * destroyed by calling its destructor as if by value().T::~T(). *this does
     * not contain a value after this call.
     */
    constexpr auto operator=(etl::nullopt_t) noexcept -> optional&
    {
        reset();
        return *this;
    }

    /**
     * @brief Assigns the state of other.
     */
    constexpr auto operator=(optional const& other) -> optional&
    {
        this->assign_from(other);
        return *this;
    }

    /**
     * @brief Perfect-forwarded assignment.
     *
     * @todo Cleanup & fix SFINAE.
     */
    template <class U = ValueType>
    constexpr auto operator=(U&& value) -> etl::enable_if_t<
        etl::conjunction_v<
            etl::negation<etl::is_same<etl::remove_cvref_t<U>, etl::optional<ValueType>>>,
            etl::is_constructible<ValueType, U>, etl::is_assignable<ValueType&, U>>,
        // && (!etl::is_scalar_v<ValueType> || !etl::is_same_v<etl::decay_t<U>,
        // ValueType>),
        optional&>
    {
        if (this->has_value())
        {
            this->get() = etl::forward<U>(value);
            return *this;
        }

        this->construct(etl::forward<U>(value));
        return *this;
    }

    /**
     * @brief Checks whether *this contains a value.
     */
    using base_type::has_value;

    /**
     * @brief Checks whether *this contains a value.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept
    {
        return has_value();
    }

    /**
     * @brief If *this contains a value, destroy that value as if by
     * value().~value_type(). Otherwise, there are no effects. *this does not
     * contain a value after this call.
     */
    using base_type::reset;

    /**
     * @brief If *this contains a value, returns a reference to the contained
     * value.
     */
    [[nodiscard]] constexpr auto value() & -> value_type&
    {
        ETL_ASSERT(this->has_value());
        return this->get();
    }

    /**
     * @brief If *this contains a value, returns a reference to the contained
     * value.
     */
    [[nodiscard]] constexpr auto value() const& -> const value_type&
    {
        ETL_ASSERT(this->has_value());
        return this->get();
    }

    /**
     * @brief If *this contains a value, returns a reference to the contained
     * value.
     */
    [[nodiscard]] constexpr auto value() && -> value_type&&
    {
        ETL_ASSERT(this->has_value());
        return this->get();
    }

    /**
     * @brief If *this contains a value, returns a reference to the contained
     * value.
     */
    [[nodiscard]] constexpr auto value() const&& -> const value_type&&
    {
        ETL_ASSERT(this->has_value());
        return this->get();
    }

    /**
     * @brief Returns the contained value if *this has a value, otherwise returns
     * default_value.
     */
    template <class U>
    [[nodiscard]] constexpr auto value_or(U&& default_value) const& -> value_type
    {
        return bool(*this) ? this->value()
                           : static_cast<value_type>(etl::forward<U>(default_value));
    }

    /**
     * @brief Returns the contained value if *this has a value, otherwise returns
     * default_value.
     */
    template <class U>
    [[nodiscard]] constexpr auto value_or(U&& default_value) && -> value_type
    {
        return bool(*this) ? etl::move(this->value())
                           : static_cast<value_type>(etl::forward<U>(default_value));
    }

    /**
     * @brief Returns a pointer to the contained value.
     */
    [[nodiscard]] constexpr auto operator->() const -> const value_type*
    {
        return &this->value();
    }

    /**
     * @brief Returns a pointer to the contained value.
     */
    [[nodiscard]] constexpr auto operator->() -> value_type* { return &this->value(); }

    /**
     * @brief Returns a reference to the contained value.
     */
    [[nodiscard]] constexpr auto operator*() const& -> const value_type&
    {
        return this->value();
    }

    /**
     * @brief Returns a reference to the contained value.
     */
    [[nodiscard]] constexpr auto operator*() & -> value_type& { return this->value(); }

    /**
     * @brief Returns a reference to the contained value.
     */
    [[nodiscard]] constexpr auto operator*() const&& -> const value_type&&
    {
        return this->value();
    }

    /**
     * @brief Returns a reference to the contained value.
     */
    [[nodiscard]] constexpr auto operator*() && -> value_type&& { return this->value(); }

    /**
     * @brief Implementation detail. Do not use!
     */
    using base_type::get;
};

/**
 * @brief One deduction guide is provided for etl::optional to account for the edge cases
 * missed by the implicit deduction guides, in particular, non-copyable arguments and
 * array to pointer conversion.
 */
template <class T>
optional(T) -> optional<T>;

}  // namespace etl
#endif  // TAETL_OPTIONAL_HPP