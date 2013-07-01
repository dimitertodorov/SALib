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
    p = sacliutil.standardOptions("customfield --customfield=<customfield name> [ <action> ]")
    p.add_option('--customfield', help="Specify a customfield.")
    (options,arguments) = p.parse_args()
    s = sacliutil.getSALib(options.username,options.password,options.authfile)

    if options.debug:
        s.setDebug(1)
    if options.customfield:
        action = ['create','delete']
        if arguments:
            if arguments[0] == 'create':
                s.createCustomField(options.customfield)
            elif arguments[0] == 'delete':
                s.deleteCustomField(options.customfield)
            else:
                p.print_help()
                print "You must provide an action: %s" % sacliutil.getActionList(action)
        else:
            p.print_help()
            print "You must provide an action: %s" % sacliutil.getActionList(action)
    else:
        p.print_help()



if __name__ == '__main__':
    try:
        main()
    except (SALib.AuthenticationFailed):
        print "customfield cmd is exiting because it couldn't authenticate the user."
    except (KeyboardInterrupt):
        print "customfield cmd is exiting because it received a Ctrl-C sequence from the keyboard."
    except OSError,args:
        print "OS had problems performing system call: %s" % args
    except SALib.RegExInvalid,args:
        print "Regular Expression is invalid the message was: %s" % args
