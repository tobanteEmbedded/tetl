/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FORMAT_MAKE_FORMAT_ARGS_HPP
#define TETL_FORMAT_MAKE_FORMAT_ARGS_HPP

#include <etl/_format/basic_format_context.hpp>
#include <etl/_format/format_arg_store.hpp>
#include <etl/_utility/forward.hpp>

namespace etl {

template <typename Context = etl::format_context, typename... Args>
auto make_format_args(Args&&... args) -> detail::format_arg_store<Context, Args...>
{
    return { forward<Args>(args)... };
}

template <typename... Args>
auto make_wformat_args(Args&&... args) -> detail::format_arg_store<wformat_context, Args...>
{
    return { forward<Args>(args)... };
}

} // namespace etl

#endif // TETL_FORMAT_MAKE_FORMAT_ARGS_HPP
