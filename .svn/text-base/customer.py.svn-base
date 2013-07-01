#!/opt/opsware/bin/python2

import os
import re
import string
import sys
import time
import optparse
import SALib
import sacliutil
import getpass

def main():
    p = sacliutil.standardOptions("customer --id=<customer name> [ <action> ]")
    p.add_option('--id', help="To specify pattern to match customer.")
    (options,arguments) = p.parse_args()
    s = sacliutil.getSALib(options.username,options.password,options.authfile)

    if options.debug:
        s.setDebug(1)
    if options.id:
        action = ['list']
        if arguments:
            if re.match('[Ll]ist',arguments[0]):
                if options.regex:
                    customerRefsList = s.getCustomerRefs(options.id,True)
                else:
                    customerRefsList = s.getCustomerRefs(options.id)
                for i in customerRefsList:
                    print "%s" % i
            else:
                p.print_help()
                print "Please provide an action: %s" % sacliutil.getActionList(action)
        else:
            p.print_help()
            print "Please provide an action: %s" % sacliutil.getActionList(action)
    else:
        p.print_help()

if __name__ == '__main__':
    try:
        main()
    except (SALib.AuthenticationFailed):
        print "customer cmd is exiting because it couldn't authenticate the user."
    except (KeyboardInterrupt):
        print "customer cmd is exiting because it received a Ctrl-C sequence from the keyboard."
    except OSError,args:
        print "OS had problems performing system call: %s" % args
    except SALib.RegExInvalid,args:
        print "Regular Expression is invalid the message was: %s" % args
    except SALib.NullSearchValue:
        print "Specified a blank value or space."
