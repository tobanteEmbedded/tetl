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

#ifndef TAETL_UNITS_UNITS_HPP
#define TAETL_UNITS_UNITS_HPP

#include "taetl/definitions.hpp"

namespace taetl::experimental::units
{
struct time
{
};
struct mass
{
};
struct length
{
};

template <typename T, typename Dimensions>
struct quantity
{
    constexpr explicit quantity(T v) : val_ {v} { }
    constexpr auto value() const { return val_; }

private:
    T val_;
};

template <typename T, typename D>
constexpr auto operator+(quantity<T, D> x, quantity<T, D> y) -> quantity<T, D>
{
    return quantity<T, D> {x.value() + y.value()};
}

template <typename T, typename D>
constexpr auto operator-(quantity<T, D> x, quantity<T, D> y) -> quantity<T, D>
{
    return quantity<T, D> {x.value() - y.value()};
}

}  // namespace taetl::experimental::units

#endif  // TAETL_UNITS_UNITS_HPP