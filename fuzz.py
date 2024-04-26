# Fuzzer $lx
from termcolor import colored


class printf:

    def __init__(self,address):
        self.result = address # need to be a list of addresses that look like this: AAAAAAA0xf7fceb9c
        self.offset_for_printf = 0
        self.potential_canary = []
        self.potential_libc = []
        self.potential_pie = []

    def print_color(offset, color,addr):
        if offset % 2 == 1:
            print(colored("{:<5} {:<30}".format(str(offset)+':',
                str(addr).replace('b', '').replace("'", '')), color))
        else:
            print(colored("{:<5} {:<30}".format(str(offset)+':',
                str(addr).replace('b', '').replace("'", '')), color), end='\t')




    def main(self):
        print_color=self.print_color
        addresses=self.result
        potential_canary=self.potential_canary
        potential_libc=self.potential_libc
        potential_pie=self.potential_pie
        ofset_for_printf=self.offset_for_printf

        for offset,result in enumerate(addresses):
            try:
                 # printf
                if ('41414141' in str(result)):
                    ofset_for_printf = offset
                    print_color(offset, "magenta", result)
                else:
                # pie
                    if (str(result).split('.')[1][0] == '5' and (str(result).split('.')[1][1] == '5' or str(result).split('.')[1][1] == '6') and str(result)[-2] != '0'):
                        potential_pie.append(offset)
                        print_color(offset, "green", result)
                    else:
                    # libc
                        if (str(result).split('.')[1][0] == '7' and str(result).split('.')[1][1] == 'f'):
                            potential_libc.append(offset)
                            print_color(offset, "blue", result)
                        else:
                
                        # canary
                            if (str(result)[-2] == '0' and str(result)[-3] == '0' and str(result).split('.')[1][0] != '5 ' and offset != ofset_for_printf and str(result).split('.')[1][0] != 'f' and str(result).count('0') <= 4):
                                potential_canary.append(offset)
                                print_color(offset, "red", result)
                            else:
                    
                                if offset % 2 == 1:
                                    print("{:<5} {:<30}".format(str(offset)+':',
                                            str(result).replace('b', '').replace("'", '')))
                                else:
                                    print("{:<5} {:<30}".format(str(offset)+':',
                                            str(result).replace('b', '').replace("'", '')), end='\t')
            except Exception as e:
                continue
        
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

    

    


a=printf(["AAAAAAA41414141"])
print(a.result)
print(a.main())
