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

#include "etl/type_traits.hpp"
#include "etl/utility.hpp"

namespace etl
{
namespace detail
{
/**
 * @brief
 */
struct optional_trivial_helper
{
    ~optional_trivial_helper() = default;
};

/**
 * @brief
 */
template <typename OptionalT>
struct optional_nontrivial_helper
{
    ~optional_nontrivial_helper()
    {
        if (auto* self = static_cast<OptionalT*>(this); self->has_value())
        {
            using value_t = typename OptionalT::value_type;
            self->value().~value_t();
        }
    }
};

}  // namespace detail

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

/**
 * @brief The class template etl::optional manages an optional contained value,
 * i.e. a value that may or may not be present.
 */
template <typename ValueT>
class optional
    : public etl::conditional_t<etl::is_trivially_destructible_v<ValueT>,
                                detail::optional_trivial_helper,
                                detail::optional_nontrivial_helper<optional<ValueT>>>
{
public:
    using value_type = ValueT;

    /**
     * @brief Constructs an object that does not contain a value.
     */
    constexpr optional() noexcept = default;

    /**
     * @brief Constructs an object that does not contain a value.
     */
    constexpr optional(etl::nullopt_t) noexcept { }

    /**
     * @brief Copy constructor.
     */
    constexpr optional(optional const& other) = default;

    /**
     * @brief Constructs an optional object that contains a value, initialized as if
     * direct-initializing.
     */
    template <typename U = value_type,
              typename   = typename etl::enable_if_t<conjunction_v<          //
                  is_constructible<ValueT, U&&>,                           //
                  negation<is_same<remove_cvref_t<U>, optional<ValueT>>>,  //
                  negation<is_same<remove_cvref_t<U>, etl::in_place_t>>    //
                  >>>
    constexpr optional(U&& value)
        : data_ {static_cast<value_type>(etl::forward<U>(value))}, has_value_ {true}
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
        // Self assignment
        if (this == &other) { return *this; }
        // If both *this and other do not contain a value, the function has no
        // effect.
        if (!this->has_value() && !other.has_value()) { return *this; }

        // If *this contains a value, but other does not, then the contained value
        // is destroyed by calling its destructor. *this does not contain a value
        // after the call.
        if (this->has_value() && !other.has_value())
        {
            this->reset();
            return *this;
        }

        // If other contains a value, then depending on whether *this contains a
        // value, the contained value is either direct-initialized or assigned from
        // *other (2) or etl::move(*other) (3). Note that a moved-from optional
        // still contains a value.
        if (other.has_value())
        {
            if (this->has_value()) { (*this) = *other; }
            else
            {
                (*this) = etl::move(*other);
            }
        }

        return *this;
    }

    /**
     * @brief Perfect-forwarded assignment.
     *
     * @todo Cleanup & fix SFINAE.
     */
    template <class U = ValueT>
    constexpr auto operator=(U&& value) -> etl::enable_if_t<
        etl::conjunction_v<
            etl::negation<etl::is_same<etl::remove_cvref_t<U>, etl::optional<ValueT>>>,
            etl::is_constructible<ValueT, U>, etl::is_assignable<ValueT&, U>>,
        // && (!etl::is_scalar_v<ValueT> || !etl::is_same_v<etl::decay_t<U>, ValueT>),
        optional&>
    {
        if (has_value()) { reset(); }
        this->data_ = etl::forward<U>(value);
        has_value_  = true;
        return *this;
    }

    /**
     * @brief Returns a pointer to the contained value.
     */
    [[nodiscard]] constexpr auto operator->() const -> const value_type*
    {
        return &data_;
    }

    /**
     * @brief Returns a pointer to the contained value.
     */
    [[nodiscard]] constexpr auto operator->() -> value_type* { return &data_; }

    /**
     * @brief Returns a reference to the contained value.
     */
    [[nodiscard]] constexpr auto operator*() const& -> const value_type& { return data_; }

    /**
     * @brief Returns a reference to the contained value.
     */
    [[nodiscard]] constexpr auto operator*() & -> value_type& { return data_; }

    /**
     * @brief Returns a reference to the contained value.
     */
    [[nodiscard]] constexpr auto operator*() const&& -> const value_type&&
    {
        return data_;
    }

    /**
     * @brief Returns a reference to the contained value.
     */
    [[nodiscard]] constexpr auto operator*() && -> value_type&& { return data_; }

    /**
     * @brief Checks whether *this contains a value.
     */
    [[nodiscard]] constexpr auto has_value() const noexcept -> bool { return has_value_; }

    /**
     * @brief Checks whether *this contains a value.
     */
    [[nodiscard]] constexpr explicit operator bool() const noexcept
    {
        return has_value();
    }

    /**
     * @brief If *this contains a value, returns a reference to the contained
     * value.
     */
    [[nodiscard]] constexpr auto value() & -> value_type& { return data_; }

    /**
     * @brief If *this contains a value, returns a reference to the contained
     * value.
     */
    [[nodiscard]] constexpr auto value() const& -> const value_type& { return data_; }

    /**
     * @brief If *this contains a value, returns a reference to the contained
     * value.
     */
    [[nodiscard]] constexpr auto value() && -> value_type&& { return data_; }

    /**
     * @brief If *this contains a value, returns a reference to the contained
     * value.
     */
    [[nodiscard]] constexpr auto value() const&& -> const value_type&& { return data_; }

    /**
     * @brief Returns the contained value if *this has a value, otherwise returns
     * default_value.
     */
    template <class U>
    [[nodiscard]] constexpr auto value_or(U&& default_value) const& -> ValueT
    {
        return bool(*this) ? **this : static_cast<ValueT>(etl::forward<U>(default_value));
    }

    /**
     * @brief Returns the contained value if *this has a value, otherwise returns
     * default_value.
     */
    template <class U>
    [[nodiscard]] constexpr auto value_or(U&& default_value) && -> ValueT
    {
        return bool(*this) ? etl::move(**this)
                           : static_cast<ValueT>(etl::forward<U>(default_value));
    }

    /**
     * @brief If *this contains a value, destroy that value as if by
     * value().~value_type(). Otherwise, there are no effects. *this does not
     * contain a value after this call.
     */
    auto reset() noexcept -> void
    {
        if (has_value()) { value().~value_type(); }

        has_value_ = false;
    }

private:
    union
    {
        char null_state_;
        ValueT data_;
    };

    bool has_value_ = false;
};

}  // namespace etl
#endif  // TAETL_OPTIONAL_HPP