# Printf_Fuzzer
This program exploits the format string C vulnerability.

## Why?
It is a simpler way to find certain addresses locally and also remotely and this means the only thing you are left to worry about is finding the correct offsets which can be done easily with gdb.

## Common Gotchas
- Make sure to pass the address like in the following to the main function of fuzz like this:

```
32-bit: AAAA14df2a00 (4 As followed by the address)
64-bit: AAAAAAAA00000000004005b0 (8 As followed by the address)
```
- Make sure to use %lx insted of %p in the format string to print the address in the correct format.



