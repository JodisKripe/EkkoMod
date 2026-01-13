# EkkoMod
This is a PoC for a simple sleep function that encrypts the image during sleep, spoofs the sleeping callstack statically and points the callbacks of timers to 8 Bytes before the NtContinue syscall stub which is essentially a `nop`
