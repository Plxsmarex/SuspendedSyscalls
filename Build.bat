@gcc -o SuspendedSyscalls.exe Main.c -T Linker.ld -e EntryPoint -Os -s -ffunction-sections -fno-asynchronous-unwind-tables -fno-ident -ffreestanding -nostartfiles -nostdlib -mno-stack-arg-probe
@objcopy -j .text -O binary SuspendedSyscalls.exe SuspendedSyscalls.bin
@pause
