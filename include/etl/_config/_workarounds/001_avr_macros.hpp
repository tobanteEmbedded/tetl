// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

// This header needs to be included after every include of a standard C
// header. AVR defines the macros listed below. It doesn't have any include
// guards on purpose.

#if defined(__AVR__)
    #undef abs
    #undef acosf
    #undef asinf
    #undef atan2f
    #undef atanf
    #undef cbrtf
    #undef ceilf
    #undef copysignf
    #undef cosf
    #undef coshf
    #undef expf
    #undef fabsf
    #undef fdimf
    #undef floorf
    #undef fmaf
    #undef fmaxf
    #undef fminf
    #undef fmodf
    #undef frexpf
    #undef hypotf
    #undef isfinitef
    #undef isinff
    #undef ldexpf
    #undef log10f
    #undef logf
    #undef lrintf
    #undef lroundf
    #undef powf
    #undef roundf
    #undef signbitf
    #undef sinf
    #undef sinhf
    #undef squaref
    #undef tanf
    #undef tanhf
    #undef truncf
#endif
