/*
Copyright (c) 2019-2021, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_CFLOAT_HPP
#define TAETL_CFLOAT_HPP

#define FLT_EVAL_METHOD __FLT_EVAL_METHOD__
#define FLT_ROUNDS (__builtin_flt_rounds())
#define FLT_RADIX __FLT_RADIX__

#define FLT_MANT_DIG __FLT_MANT_DIG__
#define DBL_MANT_DIG __DBL_MANT_DIG__
#define LDBL_MANT_DIG __LDBL_MANT_DIG__

#if __STDC_VERSION__ >= 199901L || !defined(__STRICT_ANSI__) || __cplusplus >= 201103L
#define DECIMAL_DIG __DECIMAL_DIG__
#endif

#define FLT_DIG __FLT_DIG__
#define DBL_DIG __DBL_DIG__
#define LDBL_DIG __LDBL_DIG__

#define FLT_MIN_EXP __FLT_MIN_EXP__
#define DBL_MIN_EXP __DBL_MIN_EXP__
#define LDBL_MIN_EXP __LDBL_MIN_EXP__

#define FLT_MIN_10_EXP __FLT_MIN_10_EXP__
#define DBL_MIN_10_EXP __DBL_MIN_10_EXP__
#define LDBL_MIN_10_EXP __LDBL_MIN_10_EXP__

#define FLT_MAX_EXP __FLT_MAX_EXP__
#define DBL_MAX_EXP __DBL_MAX_EXP__
#define LDBL_MAX_EXP __LDBL_MAX_EXP__

#define FLT_MAX_10_EXP __FLT_MAX_10_EXP__
#define DBL_MAX_10_EXP __DBL_MAX_10_EXP__
#define LDBL_MAX_10_EXP __LDBL_MAX_10_EXP__

#define FLT_MAX __FLT_MAX__
#define DBL_MAX __DBL_MAX__
#define LDBL_MAX __LDBL_MAX__

#define FLT_EPSILON __FLT_EPSILON__
#define DBL_EPSILON __DBL_EPSILON__
#define LDBL_EPSILON __LDBL_EPSILON__

#define FLT_MIN __FLT_MIN__
#define DBL_MIN __DBL_MIN__
#define LDBL_MIN __LDBL_MIN__

#endif  // TAETL_CFLOAT_HPP