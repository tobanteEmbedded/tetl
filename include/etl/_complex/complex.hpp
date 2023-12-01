// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_COMPLEX_COMPLEX_HPP
#define TETL_COMPLEX_COMPLEX_HPP

namespace etl {

/// \brief A complex number
/// \headerfile etl/complex.hpp
template <typename T>
struct complex {
    using value_type = T;

    constexpr complex(T const& re = T(), T const& im = T());
    constexpr complex(complex const& other);
    template <typename X>
    constexpr complex(complex<X> const& other);

    constexpr auto operator=(T const& val) -> complex<T>&;
    constexpr auto operator=(complex const& other) -> complex&;
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

private:
    value_type _real;
    value_type _imag;
};

template <typename T>
constexpr complex<T>::complex(T const& re, T const& im) : _real { re }, _imag { im }
{
}

template <typename T>
constexpr complex<T>::complex(complex const& other) : _real { other.real() }, _imag { other.imag() }
{
}

template <typename T>
template <typename X>
constexpr complex<T>::complex(complex<X> const& other) : _real { other.real() }, _imag { other.imag() }
{
}

template <typename T>
constexpr auto complex<T>::operator=(complex const& other) -> complex&
{
    _real = other._real;
    _imag = other._imag;
    return *this;
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
    (*this) *= complex<T> { val };
    return *this;
}

template <typename T>
constexpr auto complex<T>::operator/=(T const& val) -> complex<T>&
{
    (*this) /= complex<T> { val };
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
    auto const r = _real * val.real() - _imag * val.imag();
    _imag        = _real * val.imag() + _imag * val.real();
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
        return x * x + y * y;
    };

    auto const r = _real * val.real() + _imag * val.imag();
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
    return { static_cast<T>(-val.real()), static_cast<T>(-val.imag()) };
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

template <typename T>
[[nodiscard]] constexpr auto operator==(complex<T> const& lhs, complex<T> const& rhs) -> bool
{
    return lhs.real() == rhs.real() && lhs.imag() == rhs.imag();
}

template <typename T>
[[nodiscard]] constexpr auto operator==(complex<T> const& lhs, T const& rhs) -> bool
{
    return lhs == complex<T>(rhs);
}

template <typename T>
[[nodiscard]] constexpr auto operator==(T const& lhs, complex<T> const& rhs) -> bool
{
    return complex<T>(lhs) == rhs;
}

template <typename T>
[[nodiscard]] constexpr auto operator!=(complex<T> const& lhs, complex<T> const& rhs) -> bool
{
    return !(lhs == rhs);
}

template <typename T>
[[nodiscard]] constexpr auto operator!=(complex<T> const& lhs, T const& rhs) -> bool
{
    return !(lhs == rhs);
}

template <typename T>
[[nodiscard]] constexpr auto operator!=(T const& lhs, complex<T> const& rhs) -> bool
{
    return !(lhs == rhs);
}

} // namespace etl

#endif // TETL_COMPLEX_COMPLEX_HPP
