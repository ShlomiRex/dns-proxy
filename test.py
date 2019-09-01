#!/usr/bin/env python
from time import *

def a():
    sleep(5)
    return True

t=time()
print t
if(time() == t+3  or a()):
    print "AAA"