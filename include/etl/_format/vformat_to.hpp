// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_FORMAT_VFORMAT_TO_HPP
#define TETL_FORMAT_VFORMAT_TO_HPP

#include <etl/_format/basic_format_args.hpp>
#include <etl/_format/basic_format_context.hpp>
#include <etl/_iterator/back_insert_iterator.hpp>
#include <etl/_string_view/basic_string_view.hpp>
#include <etl/_utility/ignore_unused.hpp>

namespace etl {

template <typename OutputIt>
auto vformat_to(OutputIt out, string_view fmt, format_args args) -> OutputIt
{
    auto buffer = etl::detail::fmt_buffer<char>{out};
    auto it     = etl::back_inserter(buffer);
    etl::ignore_unused(fmt, args, it);
    return out;
}

} // namespace etl

#endif // TETL_FORMAT_VFORMAT_TO_HPP
