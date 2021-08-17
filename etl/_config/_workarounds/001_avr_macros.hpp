// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

/// \file This header needs to be included after every include of a standard C
/// header. AVR defines the macros listed below. It doesn't have any include
/// guards on purpose.

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
