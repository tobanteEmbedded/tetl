
/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_VARIANT_OVERLOAD_HPP
#define TETL_VARIANT_OVERLOAD_HPP

namespace etl {

template <typename... Functor>
struct overload : Functor... {
    using Functor::operator()...;
};

template <typename... Functor>
overload(Functor...) -> overload<Functor...>;

} // namespace etl

#endif // TETL_VARIANT_OVERLOAD_HPP