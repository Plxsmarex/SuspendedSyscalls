@gcc -o SuspendedSyscalls.exe IndirectSyscaller.S Main.c -e EntryPoint -T Linker.ld -Oz -s -ffunction-sections -Wl,--gc-sections -fno-asynchronous-unwind-tables -nostartfiles
@objcopy -j .text -O binary SuspendedSyscalls.exe SuspendedSyscalls.bin
@pause
