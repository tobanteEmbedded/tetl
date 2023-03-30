// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CONFIG_WORKAROUNDS_HPP
#define TETL_CONFIG_WORKAROUNDS_HPP

#if defined(__AVR__)
    // Some tests are failing on AVR builds probably due to sizeof(int) == 2 and
    // sizeof(double) != 8. Search for this macro to see all places where tests
    // are explicitly disabled.
    #define TETL_WORKAROUND_AVR_BROKEN_TESTS 1
#endif

#endif // TETL_CONFIG_WORKAROUNDS_HPP
