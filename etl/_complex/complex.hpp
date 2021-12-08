/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_COMPLEX_COMPLEX_HPP
#define TETL_COMPLEX_COMPLEX_HPP

#include "etl/_complex/complex.hpp"

namespace etl {

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
    value_type real_;
    value_type imag_;
};

template <typename T>
constexpr complex<T>::complex(T const& re, T const& im) : real_ { re }, imag_ { im }
{
}

template <typename T>
constexpr complex<T>::complex(complex const& other) : real_ { other.real() }, imag_ { other.imag() }
{
}

template <typename T>
template <typename X>
constexpr complex<T>::complex(complex<X> const& other) : real_ { other.real() }, imag_ { other.imag() }
{
}

template <typename T>
constexpr auto complex<T>::operator=(complex const& other) -> complex&
{
    real_ = other.real_;
    imag_ = other.imag_;
    return *this;
}

template <typename T>
constexpr auto complex<T>::real() const -> T
{
    return real_;
}

template <typename T>
constexpr auto complex<T>::real(T const val) -> void
{
    real_ = val;
}

template <typename T>
constexpr auto complex<T>::imag() const -> T
{
    return imag_;
}

template <typename T>
constexpr auto complex<T>::imag(T const val) -> void
{
    imag_ = val;
}

template <typename T>
constexpr auto complex<T>::operator=(T const& val) -> complex<T>&
{
    real_ = val;
    return *this;
}

template <typename T>
constexpr auto complex<T>::operator+=(T const& val) -> complex<T>&
{
    real_ += val;
    return *this;
}

template <typename T>
constexpr auto complex<T>::operator-=(T const& val) -> complex<T>&
{
    real_ -= val;
    return *this;
}

template <typename T>
constexpr auto complex<T>::operator*=(T const& val) -> complex<T>&
{
    real_ *= val;
    return *this;
}

template <typename T>
constexpr auto complex<T>::operator/=(T const& val) -> complex<T>&
{
    real_ /= val;
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

} // namespace etl

#endif // TETL_COMPLEX_COMPLEX_HPP