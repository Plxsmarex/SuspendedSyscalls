@gcc -o SuspendedSyscalls.exe IndirectSyscaller.S Main.c -e EntryPoint -T Linker.ld -Oz -s -ffunction-sections -Wl,--gc-sections -fno-asynchronous-unwind-tables -nostartfiles -nostdlib -mno-stack-arg-probe
@objcopy -j .text -O binary SuspendedSyscalls.exe SuspendedSyscalls.bin
@pause
