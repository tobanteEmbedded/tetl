// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_COMPLEX_HPP
#define TETL_COMPLEX_HPP

#include "etl/version.hpp"

namespace etl {
template <typename T>
struct complex {
    using value_type = T;

    constexpr complex(T const& re = T(), T const& im = T());
    constexpr complex(complex const&);
    template <typename X>
    constexpr complex(complex<X> const& other);

    constexpr auto operator=(T const& other) -> complex<T>&;
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
[[nodiscard]] constexpr auto operator+(complex<T> const& val) -> complex<T>;
template <typename T>
[[nodiscard]] constexpr auto operator-(complex<T> const& val) -> complex<T>;

inline namespace literals {
inline namespace complex_literals {

[[nodiscard]] constexpr auto operator""_il(long double d)
    -> complex<long double>;
[[nodiscard]] constexpr auto operator""_il(unsigned long long d)
    -> complex<long double>;
[[nodiscard]] constexpr auto operator""_i(long double d) -> complex<double>;
[[nodiscard]] constexpr auto operator""_i(unsigned long long d)
    -> complex<double>;
[[nodiscard]] constexpr auto operator""_if(long double d) -> complex<float>;
[[nodiscard]] constexpr auto operator""_if(unsigned long long d)
    -> complex<float>;

} // namespace complex_literals
} // namespace literals
} // namespace etl

namespace etl {

template <typename T>
constexpr complex<T>::complex(T const& re, T const& im)
    : real_ { re }, imag_ { im }
{
}

template <typename T>
constexpr complex<T>::complex(complex const& other)
    : real_ { other.real() }, imag_ { other.imag() }
{
}

template <typename T>
template <typename X>
constexpr complex<T>::complex(complex<X> const& other)
    : real_ { other.real() }, imag_ { other.imag() }
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

inline namespace literals {
inline namespace complex_literals {

constexpr auto operator""_il(long double d) -> complex<long double>
{
    return { 0.0L, static_cast<long double>(d) };
}

constexpr auto operator""_il(unsigned long long d) -> complex<long double>
{
    return { 0.0L, static_cast<long double>(d) };
}

constexpr auto operator""_i(long double d) -> complex<double>
{
    return { 0.0, static_cast<double>(d) };
}

constexpr auto operator""_i(unsigned long long d) -> complex<double>
{
    return { 0.0, static_cast<double>(d) };
}

constexpr auto operator""_if(long double d) -> complex<float>
{
    return { 0.0F, static_cast<float>(d) };
}

constexpr auto operator""_if(unsigned long long d) -> complex<float>
{
    return { 0.0F, static_cast<float>(d) };
}

} // namespace complex_literals
} // namespace literals

} // namespace etl

#endif // TETL_COMPLEX_HPP