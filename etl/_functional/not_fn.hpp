/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_NOT_FN_HPP
#define TETL_FUNCTIONAL_NOT_FN_HPP

#include "etl/_functional/invoke.hpp"
#include "etl/_utility/forward.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

namespace detail {
template <typename F>
struct not_fn_t {
    F f;

    template <typename... Args>
    constexpr auto operator()(Args&&... args) & noexcept(noexcept(!invoke(f, forward<Args>(args)...)))
        -> decltype(!invoke(f, forward<Args>(args)...))
    {
        return !invoke(f, forward<Args>(args)...);
    }

    template <typename... Args>
    constexpr auto operator()(Args&&... args) const& noexcept(noexcept(!invoke(f, forward<Args>(args)...)))
        -> decltype(!invoke(f, forward<Args>(args)...))
    {
        return !invoke(f, forward<Args>(args)...);
    }

    template <typename... Args>
    constexpr auto operator()(Args&&... args) && noexcept(noexcept(!invoke(move(f), forward<Args>(args)...)))
        -> decltype(!invoke(move(f), forward<Args>(args)...))
    {
        return !invoke(move(f), forward<Args>(args)...);
    }

    template <typename... Args>
    constexpr auto operator()(Args&&... args) const&& noexcept(noexcept(!invoke(move(f), forward<Args>(args)...)))
        -> decltype(!invoke(move(f), forward<Args>(args)...))
    {
        return !invoke(move(f), forward<Args>(args)...);
    }
};
} // namespace detail

template <typename F>
constexpr auto not_fn(F&& f) -> detail::not_fn_t<decay_t<F>>
{
    return { forward<F>(f) };
}

} // namespace etl

#endif // TETL_FUNCTIONAL_NOT_FN_HPP