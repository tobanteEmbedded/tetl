TOOLCHAIN 	= arm-none-eabi-

AS 			= $(TOOLCHAIN)gcc
CC 			= $(TOOLCHAIN)gcc
CXX 		= $(TOOLCHAIN)g++
LD  		= $(TOOLCHAIN)g++
OBJCOPY		= $(TOOLCHAIN)objcopy
OBJDUMP		= $(TOOLCHAIN)objdump
SIZE		= $(TOOLCHAIN)size

ARCH += --specs=nano.specs

COMMONFLAGS += -Wl,--strip-all
COMMONFLAGS += -fdevirtualize-speculatively
COMMONFLAGS += -fstack-usage

LDFLAGS += -Wl,--print-memory-usage
