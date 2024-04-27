# Fuzzer $lx
from termcolor import colored


class printf:

    def __init__(self,address):
        self.result = address # need to be a list of addresses that look like this: AAAAAAA0xf7fceb9c
        self.offset_for_printf = None
        self.potential_canary = []
        self.potential_libc = []
        self.potential_pie = []
        self.offsetlen=0
        

    def print_color(self,offset, offsetlen,color,addr):
        
        if(offsetlen%2==0):
            print("")

        # print(colored(offset,color),colored(addr, color),end="\t\t")
        #align them
        print(colored("{:<5} {:<30}".format(str(offset)+':', str(addr)),color),end="\t")




    def main(self):
        print_color=self.print_color
        addresses=self.result
        potential_canary=self.potential_canary
        potential_libc=self.potential_libc
        potential_pie=self.potential_pie
        ofset_for_printf=self.offset_for_printf
        offsetlen=self.offsetlen

        for offset,result in enumerate(addresses):
            offset+=1
            try:
                 # printf
                if ('414141' in str(result)):
                    ofset_for_printf = offset
                    offsetlen+=1
                    print_color(offset,offsetlen, "magenta", result)
                else:
                # pie
                    if (str(result).split('A')[-1][0] == '5' and (str(result).split('A')[-1][1] == '5')):
                        potential_pie.append(offset)
                        offsetlen+=1
                        print_color(offset,offsetlen, "green", result)
                    else:
                    # libc
                        if (str(result).split('A')[-1][0] == '7' and (str(result).split('A')[-1][1] == 'f') or str(result).split('A')[-1][1]=='7' ):
                            potential_libc.append(offset)
                            offsetlen+=1
                            print_color(offset,offsetlen, "blue", result)
                        else:
                
                        # canary
                            if (str(result).split('A')[-1][0]!='5' and str(result).split('A')[-1][0]!='7' and str(result).split('A')[-1][0]!='f' and str(result).split('A')[-1][-1]=='0' and str(result).split('A')[-1][-2]=='0'):
                                potential_canary.append(offset)
                                offsetlen+=1
                                print_color(offset,offsetlen ,"red", result)
                            else:
                                offsetlen+=1
                                print_color(offset,offsetlen, "white", result)

            except Exception as e:
                continue
        
        print("\n")

        if (ofset_for_printf != None):
            print("Offset for printf: ", ofset_for_printf,
                colored("-> PURPLE", "magenta"))

        if (len(potential_canary) != 0):
            print("Potential canary: ", potential_canary, colored("-> RED", "red"))

        if (len(potential_pie) != 0):
            print("Potential PIE: ", potential_pie, colored("-> GREEN", "green"))

        if (len(potential_libc) != 0):
            print("Potential libc: ", potential_libc, colored("-> BLUE", "blue"))

    






