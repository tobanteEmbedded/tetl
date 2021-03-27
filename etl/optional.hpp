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

/**
 * @file optional.hpp
 * @example optional.cpp
 */

#ifndef TAETL_OPTIONAL_HPP
#define TAETL_OPTIONAL_HPP

#include "etl/algorithm.hpp"
#include "etl/cassert.hpp"
#include "etl/memory.hpp"
#include "etl/type_traits.hpp"
#include "etl/utility.hpp"

#include "etl/detail/sfinae.hpp"

namespace etl
{
/**
 * @brief etl::nullopt_t is an empty class type used to indicate optional type
 * with uninitialized state. In particular, etl::optional has a constructor with
 * nullopt_t as a single argument, which creates an optional that does not
 * contain a value.
 *
 * @include optional.cpp
 */
struct nullopt_t
{
  explicit constexpr nullopt_t(int /*unused*/) { }
};

/**
 * @brief etl::nullopt is a constant of type etl::nullopt_t that is used to
 * indicate optional type with uninitialized state.
 */
inline constexpr auto nullopt = etl::nullopt_t {{}};

namespace detail
{
template <typename ValueType,
          bool = etl::is_trivially_destructible<ValueType>::value>
struct optional_destruct_base;

template <typename ValueType>
struct optional_destruct_base<ValueType, false>
{
  using value_type = ValueType;
  static_assert(etl::is_object_v<value_type>, "undefined behavior");

  ~optional_destruct_base()
  {
    if (has_value_) { value_.~value_type(); }
  }

  constexpr optional_destruct_base() noexcept { }

  template <typename... Args>
  constexpr explicit optional_destruct_base(etl::in_place_t /*tag*/,
                                            Args&&... args)
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
    char null_state_ {};
    value_type value_;
  };
  bool has_value_ = false;
};

template <typename ValueType>
struct optional_destruct_base<ValueType, true>
{
  using value_type = ValueType;
  static_assert(etl::is_object_v<value_type>, "undefined behavior");

  constexpr optional_destruct_base() noexcept { }

  template <typename... Args>
  constexpr explicit optional_destruct_base(etl::in_place_t /*unused*/,
                                            Args&&... args)
      : value_(etl::forward<Args>(args)...), has_value_(true)
  {
  }

  void reset() noexcept
  {
    if (has_value_) { has_value_ = false; }
  }

  union
  {
    char null_state_ {};
    value_type value_;
  };
  bool has_value_ {false};
};

template <typename ValueType, bool = etl::is_reference<ValueType>::value>
struct optional_storage_base : optional_destruct_base<ValueType>
{
  using base_t     = optional_destruct_base<ValueType>;
  using value_type = ValueType;
  using base_t::base_t;

  [[nodiscard]] constexpr auto has_value() const noexcept -> bool
  {
    return this->has_value_;
  }

  [[nodiscard]] constexpr auto get() & noexcept -> value_type&
  {
    return this->value_;
  }

  [[nodiscard]] constexpr auto get() const& noexcept -> const value_type&
  {
    return this->value_;
  }

  [[nodiscard]] constexpr auto get() && noexcept -> value_type&&
  {
    return etl::move(this->value_);
  }

  [[nodiscard]] constexpr auto get() const&& noexcept -> const value_type&&
  {
    return etl::move(this->value_);
  }

  template <typename... Args>

  void construct(Args&&... args)
  {
    ::new ((void*)etl::addressof(this->value_))
      value_type(etl::forward<Args>(args)...);
    this->has_value_ = true;
  }

  template <typename T>
  void construct_from(T&& opt)
  {
    if (opt.has_value()) { construct(etl::forward<T>(opt).get()); }
  }

  template <typename T>
  void assign_from(T&& opt)
  {
    if (this->has_value_ == opt.has_value())
    {
      if (this->has_value_) { this->value_ = etl::forward<T>(opt).get(); }
    }
    else
    {
      if (this->has_value_) { this->reset(); }
      else
      {
        construct(etl::forward<T>(opt).get());
      }
    }
  }
};

template <typename ValueType,
          bool = etl::is_trivially_copy_constructible<ValueType>::value>
struct optional_copy_base : optional_storage_base<ValueType>
{
  using optional_storage_base<ValueType>::optional_storage_base;
};

template <typename ValueType>
struct optional_copy_base<ValueType, false> : optional_storage_base<ValueType>
{
  using optional_storage_base<ValueType>::optional_storage_base;

  optional_copy_base() = default;

  optional_copy_base(optional_copy_base const& opt)
      : optional_storage_base<ValueType>::optional_storage_base {}
  {
    this->construct_from(opt);
  }

  optional_copy_base(optional_copy_base&&) noexcept = default;

  auto operator=(optional_copy_base const&) -> optional_copy_base& = default;
  auto operator            =(optional_copy_base&&) noexcept
    -> optional_copy_base& = default;
};

template <typename ValueType,
          bool = etl::is_trivially_move_constructible<ValueType>::value>
struct optional_move_base : optional_copy_base<ValueType>
{
  using optional_copy_base<ValueType>::optional_copy_base;
};

template <typename ValueType>
struct optional_move_base<ValueType, false> : optional_copy_base<ValueType>
{
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

  auto operator            =(optional_move_base&&) noexcept
    -> optional_move_base& = default;
};

template <typename ValueType,
          bool = etl::is_trivially_destructible<ValueType>::value&&
            etl::is_trivially_copy_constructible<ValueType>::value&&
              etl::is_trivially_copy_assignable<ValueType>::value>
struct optional_copy_assign_base : optional_move_base<ValueType>
{
  using optional_move_base<ValueType>::optional_move_base;
};

template <typename ValueType>
struct optional_copy_assign_base<ValueType, false>
    : optional_move_base<ValueType>
{
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

  auto operator                   =(optional_copy_assign_base&&) noexcept
    -> optional_copy_assign_base& = default;
};

template <typename ValueType,
          bool = etl::is_trivially_destructible<ValueType>::value&&
            etl::is_trivially_move_constructible<ValueType>::value&&
              etl::is_trivially_move_assignable<ValueType>::value>
struct optional_move_assign_base : optional_copy_assign_base<ValueType>
{
  using optional_copy_assign_base<ValueType>::optional_copy_assign_base;
};

template <typename ValueType>
struct optional_move_assign_base<ValueType, false>
    : optional_copy_assign_base<ValueType>
{
  using value_type = ValueType;
  using optional_copy_assign_base<ValueType>::optional_copy_assign_base;

  optional_move_assign_base() = default;

  optional_move_assign_base(optional_move_assign_base const& opt) = default;

  optional_move_assign_base(optional_move_assign_base&&) noexcept = default;

  auto operator                   =(optional_move_assign_base const&)
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
  = sfinae_ctor_base<etl::is_copy_constructible<ValueType>::value,
                     etl::is_move_constructible<ValueType>::value>;

template <typename ValueType>
using optional_sfinae_assign_base_t
  = sfinae_assign_base<(etl::is_copy_constructible<ValueType>::value
                        && etl::is_copy_assignable<ValueType>::value),
                       (etl::is_move_constructible<ValueType>::value
                        && etl::is_move_assignable<ValueType>::value)>;

}  // namespace detail

template <typename ValueType>
class optional : private detail::optional_move_assign_base<ValueType>,
                 private detail::optional_sfinae_ctor_base_t<ValueType>,
                 private detail::optional_sfinae_assign_base_t<ValueType>
{
  using base_type = detail::optional_move_assign_base<ValueType>;

  static_assert(
    !etl::is_same_v<etl::remove_cvref_t<ValueType>, etl::in_place_t>,
    "instantiation of optional with in_place_t is ill-formed");
  static_assert(!etl::is_same_v<etl::remove_cvref_t<ValueType>, etl::nullopt_t>,
                "instantiation of optional with nullopt_t is ill-formed");
  static_assert(
    !etl::is_reference_v<ValueType>,
    "instantiation of optional with a reference type is ill-formed");
  static_assert(!etl::is_array_v<ValueType>,
                "instantiation of optional with an array type is ill-formed");

  public:
  using value_type = ValueType;

  /**
   * @brief Constructs an object that does not contain a value.
   */
  constexpr optional() noexcept = default;

  /**
   * @brief Constructs an object that does not contain a value.
   */
  constexpr optional(etl::nullopt_t /*unused*/) noexcept { }

  /**
   * @brief Copy constructor.
   */
  constexpr optional(optional const&) = default;

  /**
   * @brief Move constructor.
   */
  constexpr optional(optional&&) noexcept(
    etl::is_nothrow_move_constructible_v<value_type>)
    = default;

  /**
   * @brief Constructs an optional object that contains a value, initialized as
   * if direct-initializing.
   */
  template <typename... Args,
            TAETL_REQUIRES_((is_constructible_v<value_type, Args...>))>
  constexpr explicit optional(etl::in_place_t /*unused*/, Args&&... arguments)
      : base_type(in_place, etl::forward<Args>(arguments)...)
  {
  }

  /**
   * @brief Constructs an optional object that contains a value, initialized as
   * if direct-initializing.
   */
  template <typename U = value_type,
            typename   = typename etl::enable_if_t<conjunction_v<
              is_constructible<ValueType, U&&>,
              negation<is_same<remove_cvref_t<U>, optional<ValueType>>>,
              negation<is_same<remove_cvref_t<U>, etl::in_place_t>>>>>
  constexpr optional(U&& value)
      : base_type(etl::in_place, etl::forward<U>(value))
  {
  }

  /**
   * @brief If *this contains a value before the call, the contained value is
   * destroyed by calling its destructor as if by value().T::~T(). *this does
   * not contain a value after this call.
   */
  constexpr auto operator=(etl::nullopt_t /*unused*/) noexcept -> optional&
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
  template <typename U = ValueType>
  constexpr auto operator=(U&& value) -> etl::enable_if_t<
    etl::conjunction_v<
      etl::negation<
        etl::is_same<etl::remove_cvref_t<U>, etl::optional<ValueType>>>,
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
   * @brief If the optional contains a value, returns a pointer. If empty the
   * pointer will be null.
   */
  [[nodiscard]] constexpr auto value() -> value_type*
  {
    return this->has_value() ? &this->get() : nullptr;
  }

  /**
   * @brief If the optional contains a value, returns a pointer. If empty the
   * pointer will be null.
   */
  [[nodiscard]] constexpr auto value() const -> const value_type*
  {
    return this->has_value() ? &this->get() : nullptr;
  }

  /**
   * @brief Returns the contained value if *this has a value, otherwise returns
   * default_value.
   */
  template <typename U>
  [[nodiscard]] constexpr auto value_or(U&& default_value) const& -> value_type
  {
    return has_value()
             ? *this->value()
             : static_cast<value_type>(etl::forward<U>(default_value));
  }

  /**
   * @brief Returns the contained value if *this has a value, otherwise returns
   * default_value.
   */
  template <typename U>
  [[nodiscard]] constexpr auto value_or(U&& default_value) && -> value_type
  {
    return has_value()
             ? etl::move(*this->value())
             : static_cast<value_type>(etl::forward<U>(default_value));
  }

  /**
   * @brief Returns a pointer to the contained value. The pointer is null if the
   * optional is empty.
   */
  [[nodiscard]] constexpr auto operator->() const -> const value_type*
  {
    return this->value();
  }

  /**
   * @brief Returns a pointer to the contained value. The pointer is null if the
   * optional is empty.
   */
  [[nodiscard]] constexpr auto operator->() -> value_type*
  {
    return this->value();
  }

  /**
   * @brief Swaps the contents with those of other.
   */
  constexpr auto swap(optional& other) noexcept(
    etl::is_nothrow_move_constructible_v<value_type>&&
      etl::is_nothrow_swappable_v<value_type>) -> void
  {
    // If neither *this nor other contain a value, the function has no effect.

    // If both *this and other contain values, the contained values are
    // exchanged
    if (this->has_value() == other.has_value())
    {
      using etl::swap;
      if (this->has_value()) { swap(this->get(), other.get()); }
      return;
    }

    // If only one of *this and other contains a value (let's call this object
    // in and the other un), the contained value of un is direct-initialized
    // from etl::move(*in), followed by destruction of the contained value of in
    // as if by in->T::~T(). After this call, in does not contain a value; un
    // contains a value.
    if (this->has_value())
    {
      other.construct(etl::move(this->get()));
      reset();
      return;
    }

    this->construct(etl::move(other.get()));
    other.reset();
  }

  /**
   * @brief Constructs the contained value in-place. If *this already contains a
   * value before the call, the contained value is destroyed by calling its
   * destructor.
   */
  template <typename... Args>
  constexpr auto emplace(Args&&... args) -> value_type&
  {
    this->reset();
    this->construct(etl::forward<Args>(args)...);
    return *value();
  }

  /**
   * @brief Implementation detail. Do not use!
   */
  using base_type::get;
};

/**
 * @brief Compares two optional objects, lhs and rhs.
 */
template <typename T, typename U>
[[nodiscard]] constexpr auto operator==(optional<T> const& lhs,
                                        optional<U> const& rhs) -> bool
{
  if (static_cast<bool>(lhs) != static_cast<bool>(rhs)) { return false; }
  if (!static_cast<bool>(lhs) && !static_cast<bool>(rhs)) { return true; }
  return *lhs.value() == *rhs.value();
}

/**
 * @brief Compares two optional objects, lhs and rhs.
 */
template <typename T, typename U>
[[nodiscard]] constexpr auto operator!=(optional<T> const& lhs,
                                        optional<U> const& rhs) -> bool
{
  if (static_cast<bool>(lhs) != static_cast<bool>(rhs)) { return true; }
  if (!static_cast<bool>(lhs) && !static_cast<bool>(rhs)) { return false; }
  return *lhs.value() != *rhs.value();
}

/**
 * @brief Compares two optional objects, lhs and rhs.
 */
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<(optional<T> const& lhs,
                                       optional<U> const& rhs) -> bool
{
  if (!static_cast<bool>(rhs)) { return false; }
  if (!static_cast<bool>(lhs)) { return true; }
  return *lhs.value() < *rhs.value();
}

/**
 * @brief Compares two optional objects, lhs and rhs.
 */
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>(optional<T> const& lhs,
                                       optional<U> const& rhs) -> bool
{
  if (!static_cast<bool>(lhs)) { return false; }
  if (!static_cast<bool>(rhs)) { return true; }
  return *lhs.value() > *rhs.value();
}

/**
 * @brief Compares two optional objects, lhs and rhs.
 */
template <typename T, typename U>
[[nodiscard]] constexpr auto operator<=(optional<T> const& lhs,
                                        optional<U> const& rhs) -> bool
{
  if (!static_cast<bool>(lhs)) { return true; }
  if (!static_cast<bool>(rhs)) { return false; }
  return *lhs.value() <= *rhs.value();
}

/**
 * @brief Compares two optional objects, lhs and rhs.
 */
template <typename T, typename U>
[[nodiscard]] constexpr auto operator>=(optional<T> const& lhs,
                                        optional<U> const& rhs) -> bool
{
  if (!static_cast<bool>(rhs)) { return true; }
  if (!static_cast<bool>(lhs)) { return false; }
  return *lhs.value() >= *rhs.value();
}

/**
 * @brief Compares opt with a nullopt. Equivalent to when comparing to an
 * optional that does not contain a value.
 */
template <typename T>
[[nodiscard]] constexpr auto operator==(optional<T> const& opt,
                                        etl::nullopt_t /*unused*/) noexcept
  -> bool
{
  return !opt;
}

/**
 * @brief Compares opt with a nullopt. Equivalent to when comparing to an
 * optional that does not contain a value.
 */
template <typename T>
[[nodiscard]] constexpr auto operator==(etl::nullopt_t /*unused*/,
                                        optional<T> const& opt) noexcept -> bool
{
  return !opt;
}

/**
 * @brief Compares opt with a nullopt. Equivalent to when comparing to an
 * optional that does not contain a value.
 */
template <typename T>
[[nodiscard]] constexpr auto operator!=(optional<T> const& opt,
                                        etl::nullopt_t /*unused*/) noexcept
  -> bool
{
  return static_cast<bool>(opt);
}

/**
 * @brief Compares opt with a nullopt. Equivalent to when comparing to an
 * optional that does not contain a value.
 */
template <typename T>
[[nodiscard]] constexpr auto operator!=(etl::nullopt_t /*unused*/,
                                        optional<T> const& opt) noexcept -> bool
{
  return static_cast<bool>(opt);
}

/**
 * @brief Compares opt with a nullopt. Equivalent to when comparing to an
 * optional that does not contain a value.
 */
template <typename T>
[[nodiscard]] constexpr auto operator<(optional<T> const& /*opt*/,
                                       etl::nullopt_t /*unused*/) noexcept
  -> bool
{
  return false;
}

/**
 * @brief Compares opt with a nullopt. Equivalent to when comparing to an
 * optional that does not contain a value.
 */
template <typename T>
[[nodiscard]] constexpr auto operator<(etl::nullopt_t /*unused*/,
                                       optional<T> const& opt) noexcept -> bool
{
  return static_cast<bool>(opt);
}

/**
 * @brief Compares opt with a nullopt. Equivalent to when comparing to an
 * optional that does not contain a value.
 */
template <typename T>
[[nodiscard]] constexpr auto operator<=(optional<T> const& opt,
                                        etl::nullopt_t /*unused*/) noexcept
  -> bool
{
  return !opt;
}

/**
 * @brief Compares opt with a nullopt. Equivalent to when comparing to an
 * optional that does not contain a value.
 */
template <typename T>
[[nodiscard]] constexpr auto operator<=(etl::nullopt_t /*unused*/,
                                        optional<T> const& /*opt*/) noexcept
  -> bool
{
  return true;
}

/**
 * @brief Compares opt with a nullopt. Equivalent to when comparing to an
 * optional that does not contain a value.
 */
template <typename T>
[[nodiscard]] constexpr auto operator>(optional<T> const& opt,
                                       etl::nullopt_t /*unused*/) noexcept
  -> bool
{
  return static_cast<bool>(opt);
}

/**
 * @brief Compares opt with a nullopt. Equivalent to when comparing to an
 * optional that does not contain a value.
 */
template <typename T>
[[nodiscard]] constexpr auto operator>(etl::nullopt_t /*unused*/,
                                       optional<T> const& /*opt*/) noexcept
  -> bool
{
  return false;
}

/**
 * @brief Compares opt with a nullopt. Equivalent to when comparing to an
 * optional that does not contain a value.
 */
template <typename T>
[[nodiscard]] constexpr auto operator>=(optional<T> const& /*opt*/,
                                        etl::nullopt_t /*unused*/) noexcept
  -> bool
{
  return true;
}

/**
 * @brief Compares opt with a nullopt. Equivalent to when comparing to an
 * optional that does not contain a value.
 */
template <typename T>
[[nodiscard]] constexpr auto operator>=(etl::nullopt_t /*unused*/,
                                        optional<T> const& opt) noexcept -> bool
{
  return !opt;
}

// /**
//  * @brief Compares opt with a value. The values are compared (using the
//  corresponding
//  * operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
//  * value. If the corresponding two-way comparison expression between *opt and
//  value is not
//  * well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
//  */
// template <typename T, typename U>
// constexpr auto operator==(optional<T> const&, U const &) -> bool
// {
// }

// /**
//  * @brief Compares opt with a value. The values are compared (using the
//  corresponding
//  * operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
//  * value. If the corresponding two-way comparison expression between *opt and
//  value is not
//  * well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
//  */
// template <typename T, typename U>
// constexpr auto operator==(T const&, optional<U> const&) -> bool
// {
// }

// /**
//  * @brief Compares opt with a value. The values are compared (using the
//  corresponding
//  * operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
//  * value. If the corresponding two-way comparison expression between *opt and
//  value is not
//  * well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
//  */
// template <typename T, typename U>
// constexpr auto operator!=(optional<T> const&, U const&) -> bool
// {
// }

// /**
//  * @brief Compares opt with a value. The values are compared (using the
//  corresponding
//  * operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
//  * value. If the corresponding two-way comparison expression between *opt and
//  value is not
//  * well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
//  */
// template <typename T, typename U>
// constexpr auto operator!=(T const&, optional<U> const&) -> bool
// {
// }

// /**
//  * @brief Compares opt with a value. The values are compared (using the
//  corresponding
//  * operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
//  * value. If the corresponding two-way comparison expression between *opt and
//  value is not
//  * well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
//  */
// template <typename T, typename U>
// constexpr auto operator<(optional<T> const&, U const&) -> bool
// {
// }

// /**
//  * @brief Compares opt with a value. The values are compared (using the
//  corresponding
//  * operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
//  * value. If the corresponding two-way comparison expression between *opt and
//  value is not
//  * well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
//  */
// template <typename T, typename U>
// constexpr auto operator<(T const&, optional<U> const&) -> bool
// {
// }

// /**
//  * @brief Compares opt with a value. The values are compared (using the
//  corresponding
//  * operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
//  * value. If the corresponding two-way comparison expression between *opt and
//  value is not
//  * well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
//  */
// template <typename T, typename U>
// constexpr auto operator>(optional<T> const&, U const&) -> bool
// {
// }

// /**
//  * @brief Compares opt with a value. The values are compared (using the
//  corresponding
//  * operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
//  * value. If the corresponding two-way comparison expression between *opt and
//  value is not
//  * well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
//  */
// template <typename T, typename U>
// constexpr auto operator>(T const&, optional<U> const&) -> bool
// {
// }

// /**
//  * @brief Compares opt with a value. The values are compared (using the
//  corresponding
//  * operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
//  * value. If the corresponding two-way comparison expression between *opt and
//  value is not
//  * well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
//  */
// template <typename T, typename U>
// constexpr auto operator<=(optional<T> const&, U const&) -> bool
// {
// }

// /**
//  * @brief Compares opt with a value. The values are compared (using the
//  corresponding
//  * operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
//  * value. If the corresponding two-way comparison expression between *opt and
//  value is not
//  * well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
//  */
// template <typename T, typename U>
// constexpr auto operator<=(T const&, optional<U> const&) -> bool
// {
// }

// /**
//  * @brief Compares opt with a value. The values are compared (using the
//  corresponding
//  * operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
//  * value. If the corresponding two-way comparison expression between *opt and
//  value is not
//  * well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
//  */
// template <typename T, typename U>
// constexpr auto operator>=(optional<T> const&, U const&) -> bool
// {
// }

// /**
//  * @brief Compares opt with a value. The values are compared (using the
//  corresponding
//  * operator of T) only if opt contains a value. Otherwise, opt is considered
//  less than
//  * value. If the corresponding two-way comparison expression between *opt and
//  value is not
//  * well-formed, or if its result is not convertible to bool, the program is
//  ill-formed.
//  */
// template <typename T, typename U>
// constexpr auto operator>=(T const&, optional<U> const&) -> bool
// {
// }

/**
 * @brief Creates an optional object from value.
 */
template <typename ValueType>
constexpr auto make_optional(ValueType&& value)
  -> etl::optional<etl::decay_t<ValueType>>
{
  return etl::optional<etl::decay_t<ValueType>>(etl::forward<ValueType>(value));
}

/**
 * @brief Creates an optional object constructed in-place from args...
 */
template <typename ValueType, typename... Args>
constexpr auto make_optional(Args&&... args) -> etl::optional<ValueType>
{
  return etl::optional<ValueType>(etl::in_place, etl::forward<Args>(args)...);
}

/**
 * @brief One deduction guide is provided for etl::optional to account for the
 * edge cases missed by the implicit deduction guides, in particular,
 * non-copyable arguments and array to pointer conversion.
 */
template <typename T>
optional(T) -> optional<T>;

}  // namespace etl
#endif  // TAETL_OPTIONAL_HPP