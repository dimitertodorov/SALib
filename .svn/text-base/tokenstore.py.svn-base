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
    p = sacliutil.standardOptions("tokenstore --username=<user> [ <action> ]")
    (options,arguments) = p.parse_args()
    # don't really need to get SALib instantiated.
    # s = sacliutil.getSALib(options.username,options.password)

    if options.debug:
        s.setDebug(1)
    action = ['create']
    if options.authfile or options.username:
        if arguments:
            if re.match('[Cc]reate',arguments[0]):
                if options.authfile:
                    authpath = os.path.split(options.authfile)
                    (tokenpath,tokenfile) = authpath
                else:
                    tokenpath = "%s/%s" % (sacliutil.getHomeDir(),sacliutil.defaultTokenDir)
                    tokenfile = "%s" % (options.username)            
                if not tokenfile:
                    raise SALib.InvalidArgs,authpath
                if not os.path.isdir(tokenpath):
                    os.makedirs(tokenpath,0700)
                tokenfilepath = tokenpath + "/" + tokenfile
                tkfd = os.open(tokenfilepath,os.O_RDWR|os.O_CREAT,0400)
                bytes = os.write(tkfd,SALib.getToken(username=options.username,password=options.password))
                os.close(tkfd)
        else:
            p.print_help()
            print "You have to provide either --authfile=<token filename> or --username=<username> with the actions: %s" % sacliutil.getActionList(action)
    else:
        p.print_help()
        print "You have to provide either --authfile=<token filename> or --username=<username> with the actions: %s" % sacliutil.getActionList(action)


if __name__ == '__main__':
    try:
        main()
    except (SALib.AuthenticationFailed):
        print "tokenstore cmd is exiting because it couldn't authenticate the user."
    except (KeyboardInterrupt):
        print "tokenstore cmd is exiting because it received a Ctrl-C sequence from the keyboard."
    except OSError,args:
        print "OS had problems performing system call: %s" % args
    except SALib.RegExInvalid,args:
        print "Regular Expression is invalid the message was: %s" % args
    except SALib.InvalidArgs,args:
        print "Invalid Argument, most likely a problem with the authfile path you've specified: %s" % args
