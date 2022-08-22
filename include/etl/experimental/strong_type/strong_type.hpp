/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_STRONG_TYPES_STRONG_TYPES_HPP
#define TETL_STRONG_TYPES_STRONG_TYPES_HPP

#include "etl/version.hpp"

#include "etl/utility.hpp"

namespace etl::experimental {

template <typename Type, template <typename> typename CrtpTag>
struct crtp {
    [[nodiscard]] constexpr auto underlying() const noexcept -> Type const& { return static_cast<Type const&>(*this); }

    [[nodiscard]] constexpr auto underlying() noexcept -> Type& { return static_cast<Type&>(*this); }
};

struct skill {
    template <typename StrongType>
    struct addable : crtp<StrongType, addable> {
        [[nodiscard]] constexpr auto operator+(StrongType const& other) const noexcept -> StrongType
        {
            auto const tmp = StrongType(this->underlying().raw_value() + other.raw_value());
            return tmp;
        }
    };

    template <typename StrongType>
    struct subtractable : crtp<StrongType, subtractable> {
        [[nodiscard]] constexpr auto operator-(StrongType const& other) const noexcept -> StrongType
        {
            auto const tmp = StrongType(this->underlying().raw_value() - other.raw_value());
            return tmp;
        }
    };

    template <typename StrongType>
    struct multipliable : crtp<StrongType, multipliable> {
        [[nodiscard]] constexpr auto operator*(StrongType const& other) const noexcept -> StrongType
        {
            auto const tmp = StrongType(this->underlying().raw_value() * other.raw_value());
            return tmp;
        }
    };

    template <typename StrongType>
    struct divisible : crtp<StrongType, divisible> {
        [[nodiscard]] constexpr auto operator/(StrongType const& other) const noexcept -> StrongType
        {
            auto const tmp = StrongType(this->underlying().raw_value() / other.raw_value());
            return tmp;
        }
    };

    template <typename StrongType>
    struct comparable : crtp<StrongType, comparable> {
        [[nodiscard]] constexpr friend auto operator<(StrongType const& lhs, StrongType const& rhs) noexcept -> bool
        {
            return lhs.raw_value() < rhs.raw_value();
        }

        [[nodiscard]] constexpr friend auto operator<=(StrongType const& lhs, StrongType const& rhs) noexcept -> bool
        {
            return lhs.raw_value() <= rhs.raw_value();
        }

        [[nodiscard]] constexpr friend auto operator>(StrongType const& lhs, StrongType const& rhs) noexcept -> bool
        {
            return lhs.raw_value() > rhs.raw_value();
        }

        [[nodiscard]] constexpr friend auto operator>=(StrongType const& lhs, StrongType const& rhs) noexcept -> bool
        {
            return lhs.raw_value() >= rhs.raw_value();
        }

        [[nodiscard]] constexpr friend auto operator==(StrongType const& lhs, StrongType const& rhs) noexcept -> bool
        {
            return lhs.raw_value() == rhs.raw_value();
        }

        [[nodiscard]] constexpr friend auto operator!=(StrongType const& lhs, StrongType const& rhs) noexcept -> bool
        {
            return lhs.raw_value() != rhs.raw_value();
        }
    };
};

/// \brief Wraps a built-in type. Based on C++ on Sea 2019 talk from Barney
/// Dellar. https://www.youtube.com/watch?v=fWcnp7Bulc8&t=264s
template <typename ValueType, typename Tag, template <typename> typename... Skills>
struct strong_type : Skills<strong_type<ValueType, Tag, Skills...>>... {
public:
    using value_type = ValueType;
    using tag_type   = Tag;

    constexpr explicit strong_type() noexcept = default;

    constexpr explicit strong_type(ValueType data) noexcept : rawValue_ { etl::move(data) } { }

    [[nodiscard]] constexpr auto raw_value() const noexcept -> ValueType { return rawValue_; }

private:
    ValueType rawValue_;
};
} // namespace etl::experimental

#endif // TETL_STRONG_TYPES_STRONG_TYPES_HPP
