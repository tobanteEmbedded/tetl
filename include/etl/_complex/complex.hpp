// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_COMPLEX_HPP
#define TETL_COMPLEX_COMPLEX_HPP

#include <etl/_cstddef/size_t.hpp>
#include <etl/_tuple/is_tuple_like.hpp>
#include <etl/_tuple/tuple_element.hpp>
#include <etl/_tuple/tuple_size.hpp>
#include <etl/_type_traits/integral_constant.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

/// \brief A complex number
/// \headerfile etl/complex.hpp
/// \ingroup complex
template <typename T>
struct complex {
    using value_type = T;

    constexpr complex(T const& re = T(), T const& im = T());
    constexpr complex(complex const& other) = default;
    template <typename X>
    explicit(sizeof(X) > sizeof(T)) constexpr complex(complex<X> const& other);

    constexpr auto operator=(T const& val) -> complex<T>&;
    constexpr auto operator=(complex const& other) -> complex& = default;
    template <typename X>
    constexpr auto operator=(complex<X> const& other) -> complex<T>&;

    [[nodiscard]] constexpr auto real() const -> T;
    constexpr auto real(T val) -> void;

    [[nodiscard]] constexpr auto imag() const -> T;
    constexpr auto imag(T val) -> void;

    constexpr auto operator+=(T const& val) -> complex<T>&;
    constexpr auto operator-=(T const& val) -> complex<T>&;
    constexpr auto operator*=(T const& val) -> complex<T>&;
    constexpr auto operator/=(T const& val) -> complex<T>&;

    template <typename X>
    constexpr auto operator+=(complex<X> const& val) -> complex<T>&;
    template <typename X>
    constexpr auto operator-=(complex<X> const& val) -> complex<T>&;
    template <typename X>
    constexpr auto operator*=(complex<X> const& val) -> complex<T>&;
    template <typename X>
    constexpr auto operator/=(complex<X> const& val) -> complex<T>&;

    template <size_t I, typename X>
    friend constexpr auto get(complex<X>&) noexcept -> X&;

    template <size_t I, typename X>
    friend constexpr auto get(complex<X>&&) noexcept -> X&&;

    template <size_t I, typename X>
    friend constexpr auto get(complex<X> const&) noexcept -> X const&;

    template <size_t I, typename X>
    friend constexpr auto get(complex<X> const&&) noexcept -> X const&&;

    friend constexpr auto operator==(complex const& lhs, complex const& rhs) -> bool
    {
        return lhs.real() == rhs.real() and lhs.imag() == rhs.imag();
    }

    friend constexpr auto operator==(complex const& lhs, T const& rhs) -> bool
    {
        return lhs.real() == rhs and lhs.imag() == T{};
    }

private:
    value_type _real;
    value_type _imag;
};

template <typename T>
inline constexpr auto is_tuple_like<etl::complex<T>> = true;

template <typename T>
struct tuple_size<etl::complex<T>> : etl::integral_constant<etl::size_t, 2> { };

template <size_t I, typename T>
struct tuple_element<I, etl::complex<T>> {
    static_assert(I < 2, "Index out of range for etl::complex");
    using type = T;
};

template <size_t I, typename X>
constexpr auto get(complex<X>& z) noexcept -> X&
{
    static_assert(I < 2, "Index out of range for etl::complex");
    if constexpr (I == 0) {
        return z._real;
    } else {
        return z._imag;
    }
}

template <size_t I, typename X>
constexpr auto get(complex<X>&& z) noexcept -> X&&
{
    static_assert(I < 2, "Index out of range for etl::complex");
    if constexpr (I == 0) {
        return etl::move(z._real);
    } else {
        return etl::move(z._imag);
    }
}

template <size_t I, typename X>
constexpr auto get(complex<X> const& z) noexcept -> X const&
{
    static_assert(I < 2, "Index out of range for etl::complex");
    if constexpr (I == 0) {
        return z._real;
    } else {
        return z._imag;
    }
}

template <size_t I, typename X>
constexpr auto get(complex<X> const&& z) noexcept -> X const&&
{
    static_assert(I < 2, "Index out of range for etl::complex");
    if constexpr (I == 0) {
        return etl::move(z._real);
    } else {
        return etl::move(z._imag);
    }
}

template <typename T>
constexpr complex<T>::complex(T const& re, T const& im)
    : _real{re}
    , _imag{im}
{
}

template <typename T>
template <typename X>
constexpr complex<T>::complex(complex<X> const& other)
    : _real{static_cast<T>(other.real())}
    , _imag{static_cast<T>(other.imag())}
{
}

template <typename T>
constexpr auto complex<T>::real() const -> T
{
    return _real;
}

template <typename T>
constexpr auto complex<T>::real(T const val) -> void
{
    _real = val;
}

template <typename T>
constexpr auto complex<T>::imag() const -> T
{
    return _imag;
}

template <typename T>
constexpr auto complex<T>::imag(T const val) -> void
{
    _imag = val;
}

template <typename T>
constexpr auto complex<T>::operator=(T const& val) -> complex<T>&
{
    _real = val;
    _imag = T{};
    return *this;
}

template <typename T>
constexpr auto complex<T>::operator+=(T const& val) -> complex<T>&
{
    _real += val;
    return *this;
}

template <typename T>
constexpr auto complex<T>::operator-=(T const& val) -> complex<T>&
{
    _real -= val;
    return *this;
}

template <typename T>
constexpr auto complex<T>::operator*=(T const& val) -> complex<T>&
{
    (*this) *= complex<T>{val};
    return *this;
}

template <typename T>
constexpr auto complex<T>::operator/=(T const& val) -> complex<T>&
{
    (*this) /= complex<T>{val};
    return *this;
}

template <typename T>
template <typename X>
constexpr auto complex<T>::operator+=(complex<X> const& val) -> complex<T>&
{
    _real += val.real();
    _imag += val.imag();
    return *this;
}

template <typename T>
template <typename X>
constexpr auto complex<T>::operator-=(complex<X> const& val) -> complex<T>&
{
    _real -= val.real();
    _imag -= val.imag();
    return *this;
}

template <typename T>
template <typename X>
constexpr auto complex<T>::operator*=(complex<X> const& val) -> complex<T>&
{
    auto const r = static_cast<T>(_real * val.real() - _imag * val.imag());
    _imag        = static_cast<T>(_real * val.imag() + _imag * val.real());
    _real        = r;
    return *this;
}

template <typename T>
template <typename X>
constexpr auto complex<T>::operator/=(complex<X> const& val) -> complex<T>&
{
    auto const norm = [](auto const& c) {
        auto const x = c.real();
        auto const y = c.imag();
        return static_cast<T>(x * x + y * y);
    };

    auto const r = static_cast<T>(_real * val.real() + _imag * val.imag());
    auto const n = norm(val);
    _imag        = (_imag * val.real() - _real * val.imag()) / n;
    _real        = r / n;
    return *this;
}

template <typename T>
constexpr auto operator+(complex<T> const& val) -> complex<T>
{
    return val;
}

template <typename T>
constexpr auto operator-(complex<T> const& val) -> complex<T>
{
    return {static_cast<T>(-val.real()), static_cast<T>(-val.imag())};
}

template <typename T>
[[nodiscard]] constexpr auto operator+(complex<T> const& lhs, complex<T> const& rhs) -> complex<T>
{
    return complex<T>(lhs) += rhs;
}

template <typename T>
[[nodiscard]] constexpr auto operator+(complex<T> const& lhs, T const& rhs) -> complex<T>
{
    return complex<T>(lhs) += rhs;
}

template <typename T>
[[nodiscard]] constexpr auto operator+(T const& lhs, complex<T> const& rhs) -> complex<T>
{
    return complex<T>(lhs) += rhs;
}

template <typename T>
[[nodiscard]] constexpr auto operator-(complex<T> const& lhs, complex<T> const& rhs) -> complex<T>
{
    return complex<T>(lhs) -= rhs;
}

template <typename T>
[[nodiscard]] constexpr auto operator-(complex<T> const& lhs, T const& rhs) -> complex<T>
{
    return complex<T>(lhs) -= rhs;
}

template <typename T>
[[nodiscard]] constexpr auto operator-(T const& lhs, complex<T> const& rhs) -> complex<T>
{
    return complex<T>(lhs) -= rhs;
}

template <typename T>
[[nodiscard]] constexpr auto operator*(complex<T> const& lhs, complex<T> const& rhs) -> complex<T>
{
    return complex<T>(lhs) *= rhs;
}

template <typename T>
[[nodiscard]] constexpr auto operator*(complex<T> const& lhs, T const& rhs) -> complex<T>
{
    return complex<T>(lhs) *= rhs;
}

template <typename T>
[[nodiscard]] constexpr auto operator*(T const& lhs, complex<T> const& rhs) -> complex<T>
{
    return complex<T>(lhs) *= rhs;
}

template <typename T>
[[nodiscard]] constexpr auto operator/(complex<T> const& lhs, complex<T> const& rhs) -> complex<T>
{
    return complex<T>(lhs) /= rhs;
}

template <typename T>
[[nodiscard]] constexpr auto operator/(complex<T> const& lhs, T const& rhs) -> complex<T>
{
    return complex<T>(lhs) /= rhs;
}

template <typename T>
[[nodiscard]] constexpr auto operator/(T const& lhs, complex<T> const& rhs) -> complex<T>
{
    return complex<T>(lhs) /= rhs;
}

// NOLINTNEXTLINE(modernize-concat-nested-namespaces)
inline namespace literals {
inline namespace complex_literals {

constexpr auto operator""_il(long double d) -> complex<long double> { return {0.0L, static_cast<long double>(d)}; }

constexpr auto operator""_il(unsigned long long d) -> complex<long double>
{
    return {0.0L, static_cast<long double>(d)};
}

constexpr auto operator""_i(long double d) -> complex<double> { return {0.0, static_cast<double>(d)}; }

constexpr auto operator""_i(unsigned long long d) -> complex<double> { return {0.0, static_cast<double>(d)}; }

constexpr auto operator""_if(long double d) -> complex<float> { return {0.0F, static_cast<float>(d)}; }

constexpr auto operator""_if(unsigned long long d) -> complex<float> { return {0.0F, static_cast<float>(d)}; }

} // namespace complex_literals
} // namespace literals

} // namespace etl

#endif // TETL_COMPLEX_COMPLEX_HPP
