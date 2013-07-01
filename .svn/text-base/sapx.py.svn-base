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
    p = sacliutil.standardOptions("")
    p.add_option('--id', help="Specify ID or APX name.")
    p.add_option('--notification', action="store_true",help="Emails notification to the user.")
    p.add_option('--ticketid', help="Ticket ID to assign the APX.")
    p.add_option('--args', help="Arguments to pass to the APX.")
    (options,arguments) = p.parse_args()
    s = sacliutil.getSALib(options.username,options.password,options.authfile)

    if options.debug:
        s.setDebug(1)
    if options.id:
        action = ['run','list']
        if arguments:
            if re.match('[Rr]un',arguments[0]):
                if options.args:
                    args = options.args
                else:
                    args = ''
                if options.ticketid:
                    ticketid = options.ticketid
                else:
                    ticketid = None
                jobid = s.startProgramAPX(options.id,args,options.notification,ticketid)
                print "%s" % jobid
            elif re.match('[Ll]ist',arguments[0]):
                for i in s.getAPXRefs(options.id):
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
        print "sacli is exiting because it couldn't authenticate the user."
    except (KeyboardInterrupt):
        print "sacli is exiting because it received a Ctrl-C sequence from the keyboard."
    except OSError,args:
        print "OS had problems performing system call: %s" % args
    except SALib.RegExInvalid,args:
        print "Regular Expression is invalid the message was: %s" % args
