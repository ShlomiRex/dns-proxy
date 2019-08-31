import sendDnsTest_ourServer as dns


def print_console():
    print "[0] <exit>"
    print "[1] Google"
    print "[2] YouTube"

while True:
    print_console()
    num = input("Enter your function number to run: ")
    if num == 0:
        exit()
    elif num == 1:
        dns.google()
    elif num == 2:
        dns.youtube()
    print "\n\n"
