/*
Copyright (c) Tobias Hienzsch. All rights reserved.

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

#ifndef TAETL_STRONG_TYPES_STRONG_TYPES_HPP
#define TAETL_STRONG_TYPES_STRONG_TYPES_HPP

#include "etl/crtp.hpp"
#include "etl/utility.hpp"

namespace etl::experimental
{
struct skill
{
  template <typename StrongType>
  struct addable : crtp<StrongType, addable>
  {
    [[nodiscard]] constexpr auto
    operator+(StrongType const& other) const noexcept -> StrongType
    {
      auto const tmp
        = StrongType(this->underlying().raw_value() + other.raw_value());
      return tmp;
    }
  };

  template <typename StrongType>
  struct subtractable : crtp<StrongType, subtractable>
  {
    [[nodiscard]] constexpr auto
    operator-(StrongType const& other) const noexcept -> StrongType
    {
      auto const tmp
        = StrongType(this->underlying().raw_value() - other.raw_value());
      return tmp;
    }
  };

  template <typename StrongType>
  struct multipliable : crtp<StrongType, multipliable>
  {
    [[nodiscard]] constexpr auto
    operator*(StrongType const& other) const noexcept -> StrongType
    {
      auto const tmp
        = StrongType(this->underlying().raw_value() * other.raw_value());
      return tmp;
    }
  };

  template <typename StrongType>
  struct divisible : crtp<StrongType, divisible>
  {
    [[nodiscard]] constexpr auto
    operator/(StrongType const& other) const noexcept -> StrongType
    {
      auto const tmp
        = StrongType(this->underlying().raw_value() / other.raw_value());
      return tmp;
    }
  };

  template <typename StrongType>
  struct comparable : crtp<StrongType, comparable>
  {
    [[nodiscard]] constexpr friend auto
    operator<(StrongType const& lhs, StrongType const& rhs) noexcept -> bool
    {
      return lhs.raw_value() < rhs.raw_value();
    }

    [[nodiscard]] constexpr friend auto
    operator<=(StrongType const& lhs, StrongType const& rhs) noexcept -> bool
    {
      return lhs.raw_value() <= rhs.raw_value();
    }

    [[nodiscard]] constexpr friend auto
    operator>(StrongType const& lhs, StrongType const& rhs) noexcept -> bool
    {
      return lhs.raw_value() > rhs.raw_value();
    }

    [[nodiscard]] constexpr friend auto
    operator>=(StrongType const& lhs, StrongType const& rhs) noexcept -> bool
    {
      return lhs.raw_value() >= rhs.raw_value();
    }

    [[nodiscard]] constexpr friend auto
    operator==(StrongType const& lhs, StrongType const& rhs) noexcept -> bool
    {
      return lhs.raw_value() == rhs.raw_value();
    }

    [[nodiscard]] constexpr friend auto
    operator!=(StrongType const& lhs, StrongType const& rhs) noexcept -> bool
    {
      return lhs.raw_value() != rhs.raw_value();
    }
  };
};

/**
 * @brief Wraps a built-in type.
 * @details Based on C++ on Sea 2019 talk from Barney Dellar.
 * https://www.youtube.com/watch?v=fWcnp7Bulc8&t=264s
 */
template <typename ValueType, typename Tag,
          template <typename> typename... Skills>
struct strong_type : Skills<strong_type<ValueType, Tag, Skills...>>...
{
  public:
  using value_type = ValueType;
  using tag_type   = Tag;

  constexpr explicit strong_type() noexcept = default;

  constexpr explicit strong_type(ValueType data) noexcept
      : rawValue_ {etl::move(data)}
  {
  }

  [[nodiscard]] constexpr auto raw_value() const noexcept -> ValueType
  {
    return rawValue_;
  }

  private:
  ValueType rawValue_;
};
}  // namespace etl::experimental

#endif  // TAETL_STRONG_TYPES_STRONG_TYPES_HPP
