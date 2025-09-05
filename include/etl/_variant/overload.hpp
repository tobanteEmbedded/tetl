// SPDX-License-Identifier: BSL-1.0

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
