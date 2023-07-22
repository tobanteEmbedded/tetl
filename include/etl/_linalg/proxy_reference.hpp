// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LINALG_PROXY_REFERENCE_HPP
#define TETL_LINALG_PROXY_REFERENCE_HPP

#include <etl/_linalg/concepts.hpp>
#include <etl/_type_traits/is_base_of.hpp>

namespace etl::linalg::detail {

struct proxy_reference_base { };

template <typename Reference, typename Value, typename Derived>
struct proxy_reference : proxy_reference_base {
    using reference_type = Reference;
    using value_type     = Value;
    using derived_type   = Derived;

    constexpr explicit proxy_reference(Reference reference) : reference_(reference) { }

    constexpr operator value_type() const // NOLINT(readability-const-return-type)
    {
        return static_cast<Derived const&>(*this).to_value(reference_);
    }

    constexpr friend auto operator-(derived_type const& cs) { return -value_type(cs); }

    template <typename Rhs>
        requires(is_base_of_v<proxy_reference_base, Rhs>)
    constexpr friend auto operator+(derived_type lhs, Rhs rhs)
    {
        using rhs_value_type = typename Rhs::value_type;
        return value_type(lhs) + rhs_value_type(rhs);
    }

    template <typename Rhs>
        requires(not is_base_of_v<proxy_reference_base, Rhs>)
    constexpr friend auto operator+(derived_type lhs, Rhs rhs)
    {
        return value_type(lhs) + rhs;
    }

    template <typename Lhs>
        requires(not is_base_of_v<proxy_reference_base, Lhs>)
    constexpr friend auto operator+(Lhs lhs, derived_type rhs)
    {
        return lhs + value_type(rhs);
    }

    template <typename Rhs>
        requires(is_base_of_v<proxy_reference_base, Rhs>)
    constexpr friend auto operator-(derived_type lhs, Rhs rhs)
    {
        using rhs_value_type = typename Rhs::value_type;
        return value_type(lhs) - rhs_value_type(rhs);
    }

    template <typename Rhs>
        requires(not is_base_of_v<proxy_reference_base, Rhs>)
    constexpr friend auto operator-(derived_type lhs, Rhs rhs)
    {
        return value_type(lhs) - rhs;
    }

    template <typename Lhs>
        requires(not is_base_of_v<proxy_reference_base, Lhs>)
    constexpr friend auto operator-(Lhs lhs, derived_type rhs)
    {
        return lhs - value_type(rhs);
    }

    template <typename Rhs>
        requires(is_base_of_v<proxy_reference_base, Rhs>)
    constexpr friend auto operator*(derived_type lhs, Rhs rhs)
    {
        using rhs_value_type = typename Rhs::value_type;
        return value_type(lhs) * rhs_value_type(rhs);
    }

    template <typename Rhs>
        requires(not is_base_of_v<proxy_reference_base, Rhs>)
    constexpr friend auto operator*(derived_type lhs, Rhs rhs)
    {
        return value_type(lhs) * rhs;
    }

    template <typename Lhs>
        requires(not is_base_of_v<proxy_reference_base, Lhs>)
    constexpr friend auto operator*(Lhs lhs, derived_type rhs)
    {
        return lhs * value_type(rhs);
    }

    template <typename Rhs>
        requires(is_base_of_v<proxy_reference_base, Rhs>)
    constexpr friend auto operator/(derived_type lhs, Rhs rhs)
    {
        using rhs_value_type = typename Rhs::value_type;
        return value_type(lhs) / rhs_value_type(rhs);
    }

    template <typename Rhs>
        requires(not is_base_of_v<proxy_reference_base, Rhs>)
    constexpr friend auto operator/(derived_type lhs, Rhs rhs)
    {
        return value_type(lhs) / rhs;
    }

    template <typename Lhs>
        requires(not is_base_of_v<proxy_reference_base, Lhs>)
    constexpr friend auto operator/(Lhs lhs, derived_type rhs)
    {
        return lhs / value_type(rhs);
    }

    constexpr friend auto abs(derived_type const& x)
    {
        return abs_if_needed(value_type(static_cast<this_type const&>(x)));
    }

    constexpr friend auto real(derived_type const& x)
    {
        return real_if_needed(value_type(static_cast<this_type const&>(x)));
    }

    constexpr friend auto imag(derived_type const& x)
    {
        return imag_if_needed(value_type(static_cast<this_type const&>(x)));
    }

    constexpr friend auto conj(derived_type const& x)
    {
        return conj_if_needed(value_type(static_cast<this_type const&>(x)));
    }

private:
    using this_type = proxy_reference<Reference, Value, Derived>;
    Reference reference_;
};

} // namespace etl::linalg::detail

#endif // TETL_LINALG_PROXY_REFERENCE_HPP
