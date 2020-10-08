TOOLCHAIN 	= arm-none-eabi-

AS 			= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)gcc
CC 			= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)gcc
CXX 		= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)g++
LD  		= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)g++
OBJCOPY		= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)objcopy
OBJDUMP		= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)objdump
SIZE		= $(TOOLCHAIN_BIN)/$(TOOLCHAIN)size

ARCH += --specs=nano.specs

COMMONFLAGS += -Wl,--strip-all
COMMONFLAGS += -fdevirtualize-speculatively
COMMONFLAGS += -fstack-usage

LDFLAGS += -Wl,--print-memory-usage
