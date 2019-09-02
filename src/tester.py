import proxy
import attacker
from threading import Thread
import random

NEW_WAIT4ANSWERS_SECONDS = 0.3
NEW_SPAM_SECONDS = 0.5

def test1():
    print "\n-----------------------------"
    print "[Test1]"
    proxy.WAIT4ANSWERS_SECONDS = NEW_WAIT4ANSWERS_SECONDS
    attacker.SPAM_SECONDS = NEW_SPAM_SECONDS

    thread = Thread(target = attacker.amit_test1)
    thread.start()
    status, ans, answers_cache = proxy.begin("www.amitdvir.com")
    thread.join()
    print "STATUS = " + str(status)
    print "ANS = " + str(ans)
    
    assert(status == 1)
    assert(ans==[])

def test2():
    print "\n-----------------------------"
    print "[Test2]"
    proxy.WAIT4ANSWERS_SECONDS = NEW_WAIT4ANSWERS_SECONDS
    attacker.SPAM_SECONDS = NEW_SPAM_SECONDS

    thread = Thread(target = attacker.amit_test2)
    thread.start()
    status, ans, answers_cache = proxy.begin("www.amitdvir.com")
    thread.join()
    print "STATUS = " + str(status)
    print "ANS = " + str(ans)
    
    assert(status == 0)
    assert(ans==[attacker.amitdvir_real_ip])



def test3():
    print "\n-----------------------------"
    print "[Test3]"
    proxy.WAIT4ANSWERS_SECONDS = NEW_WAIT4ANSWERS_SECONDS
    attacker.SPAM_SECONDS = NEW_SPAM_SECONDS

    thread = Thread(target = attacker.amit_test3)
    thread.start()
    status, ans, answers_cache = proxy.begin("www.amitdvir.com")
    thread.join()
    print "STATUS = " + str(status)
    print "ANS = " + str(ans)
    
    assert(status == 0)
    assert(ans==[attacker.amitdvir_real_ip])



def test4():
    print "\n-----------------------------"
    print "[Test4]"
    proxy.WAIT4ANSWERS_SECONDS = NEW_WAIT4ANSWERS_SECONDS
    attacker.SPAM_SECONDS = NEW_SPAM_SECONDS

    thread = Thread(target = attacker.amit_test4)
    thread.start()
    status, ans, answers_cache = proxy.begin("www.amitdvir.com")
    thread.join()
    print "STATUS = " + str(status)
    print "ANS = " + str(ans)
    
    assert(status == 1)
    assert(ans==[])

def test5():
    print "\n-----------------------------"
    print "[Test5]"
    proxy.WAIT4ANSWERS_SECONDS = NEW_WAIT4ANSWERS_SECONDS
    attacker.SPAM_SECONDS = NEW_SPAM_SECONDS

    thread = Thread(target = attacker.amit_test4)
    thread.start()
    status, ans, answers_cache = proxy.begin("www.amitdvir.com")
    thread.join()
    print "STATUS = " + str(status)
    print "ANS = " + str(ans)
    
    assert(status == 0)
    assert(ans==[attacker.amitdvir_real_ip])


#www.geeksforgeeks.org

'''
test1()
test2()
test3()
test4()
test5()
'''

Success_Wait4Answers = []
Success_SpamRND = []

Failiures_Wait4Answers = []
Failiures_SpamRND = []


def autoTester(test):

    wait4answers_rnd = random.uniform(0.3, 0.4)
    spam_rnd = random.uniform(0.3, 0.4)
    

    NEW_WAIT4ANSWERS_SECONDS = wait4answers_rnd
    NEW_SPAM_SECONDS = spam_rnd
    try:
        test()
        #print "Success: " 
        #print str(wait4answers_rnd) + " | " + str(spam_rnd)
        Success_Wait4Answers.append(wait4answers_rnd)
        Success_SpamRND.append(spam_rnd)
    except AssertionError:
        #print "Failiure: " 
        #print str(wait4answers_rnd) + " | " + str(spam_rnd)
        Failiures_Wait4Answers.append(wait4answers_rnd)
        Failiures_SpamRND.append(spam_rnd)


try:
    max = 10
    for i in range(max):
        proxy.DEBUG_CACHE = True
        autoTester(test1)
        autoTester(test2)
        autoTester(test3)
        autoTester(test4)
        autoTester(test5)
    for i in range(max):
        proxy.DEBUG_CACHE = False
        autoTester(test1)
        autoTester(test2)
        autoTester(test3)
        autoTester(test4)
        autoTester(test5)
except KeyboardInterrupt:
    pass


def Average(lst): 
    return sum(lst) / len(lst) 

print "Average success time for Wait4Answers:"
print Average(Success_Wait4Answers)

print "Average success time for Spam:"
print Average(Success_SpamRND)

print "Minimum time for Wait4Answers:"
print str(min(Success_Wait4Answers))

print "Minimum time for Spam:"
print str(min(Success_SpamRND))
