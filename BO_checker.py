import os
from mmap import mmap, PROT_READ
import re
import sys

def strings(fname, n=6):
    with open(fname, 'rb') as f, mmap(f.fileno(), 0, prot=PROT_READ) as m:
        for match in re.finditer(('([\w/]{%s}[\w/]*)' % n).encode(), m):
            yield match.group(0)
def lists_overlap(a, b):
  sb = set(b)
  return any(itertools.imap(sb.__contains__, a))
       
if __name__ == '__main__':
    #file = input("Please provide the absolute path to the binary you want to analyze ex: /bin/bash: ")
    stgggss = []
    present_BO_strings = []
    stgs_output = strings(sys.argv[1])
    for stgs in stgs_output:
        stgggss.append((stgs.decode("utf-8")))
    bo_ftn = ["strcpy","gets","scanf","strcat"]
    if bool(set(bo_ftn) & set(stgggss)) :
        for word in bo_ftn:
            if word in stgggss:
                present_BO_strings.append(word)
        print("Potential Buffer overflow possible , biniary uses the fuction", present_BO_strings[:], "Known to have history of BO!!")
                
    else:
        print("Buffer overflow possible , biniary uses the fuction", (word).decode("utf-8"), "Known to have history of BO!!")

