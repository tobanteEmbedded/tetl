// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_EXCEPTION_RAISE_HPP
#define TETL_EXCEPTION_RAISE_HPP

#include <etl/_config/all.hpp>

#include <etl/_cassert/assert.hpp>
#include <etl/_exception/exception.hpp>
#include <etl/_source_location/source_location.hpp>

namespace etl {

template <typename Exception>
[[noreturn]] TETL_NO_INLINE TETL_COLD auto
raise(char const* msg, etl::source_location const loc = etl::source_location::current()) -> void
{
#if defined(TETL_ENABLE_CUSTOM_EXCEPTION_HANDLER)
    (void)loc;
    etl::exception_handler(Exception{msg});
#else
    etl::assert_handler(
        etl::assert_msg{
            static_cast<int>(loc.line()),
            loc.file_name(),
            loc.function_name(),
            Exception{msg}.what(),
        }
    );
#endif
}

} // namespace etl

#endif // TETL_EXCEPTION_RAISE_HPP
