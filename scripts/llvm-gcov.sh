#!/bin/bash
# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch
exec llvm-cov-21 gcov "$@"
