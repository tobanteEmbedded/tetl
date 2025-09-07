// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_CONFIG_USER_HPP
#define TETL_CONFIG_USER_HPP

#if defined(TETL_ENABLE_USER_CONFIG_HEADER_INCLUDE)
    #if (__has_include(<tetl_config.hpp>))
        #include <tetl_config.hpp>
    #else
        #error "config header <tetl_config.hpp> could not be found"
    #endif
#endif

#endif // TETL_CONFIG_USER_HPP
