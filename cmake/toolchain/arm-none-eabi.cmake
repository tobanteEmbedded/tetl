# SPDX-License-Identifier: BSL-1.0
# SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

set(MCU -mcpu=cortex-m7 -mthumb -mfloat-abi=hard -mfpu=fpv5-d16)
add_compile_options(${MCU})
add_link_options(${MCU})
