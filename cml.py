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
    p = sacliutil.standardOptions("cml --id=<customer name> [ <action> ]")
    p.add_option('--id', help="To specify pattern to match cmls.")
    p.add_option('--platform', help="Specify a platform either by id, name, or pattern match.")
    p.add_option('--directory', help="Directory where cml will be written to.")
    (options,arguments) = p.parse_args()
    s = sacliutil.getSALib(options.username,options.password,options.authfile)

    if options.debug:
        s.setDebug(1)
    if options.id:
        action = ['list','stdout','fileout','addplatform','updateplatform']
        if arguments:
            if re.match('[Ll]ist$',arguments[0]):
                for i in s.getCMLRefs(options.id,options.regex):
                    try:
                        if s.isHPSA9x():
                            print "%s|%s" % (sacliutil.printObjectPath(s,[i]),sacliutil.printObjectID(i))
                        else:
                            print "%s|%s" % (i,sacliutil.printObjectID(i))
                    except SALib.AuthorizationDeniedException:
                        print "!!!%s is INACCESSIBLE!!!" % i
                        continue
                    except SALib.NotInFolder,i:
                        print "!!!%s is INACCESSIBLE!!!" % i
                        continue
            elif re.match('[Ss]tdout$',arguments[0]):
                cmlvos = s.getCMLVOs(s.getCMLRefs(options.id,options.regex))
                for cmlvo in cmlvos:
                    print "%s" % cmlvo.text
            elif re.match('[Ff]ileout$',arguments[0]):
                cmlvos = s.getCMLVOs(s.getCMLRefs(options.id,options.regex))
                if options.directory:
                    if os.path.isdir(options.directory):
                        for cmlvo in cmlvos:
                            try:
                                print "Writing to file: %s" % os.path.join(options.directory,cmlvo.name)      
                                output_file = open(os.path.join(options.directory,cmlvo.name), 'w')
                                output_file.write(cmlvo.text)
                                output_file.close()
                            except IOError,args:
                                raise OSError,"%s %s" % (args.strerror, args.filename)
                    else:
                        raise OSError,"No such directory"
                else:
                    for cmlvo in cmlvos:
                        print "Writing to file: %s" % cmlvo.name                    
                        output_file = open(cmlvo.name, 'w')
                        output_file.write(cmlvo.text)
                        output_file.close()
            elif re.match('(?i)addplatform?',arguments[0]):
                if options.platform:
                    print "Adding platform on the following cml(s):"
                    for cmlvo in s.addCMLPlatform(options.id,options.platform,options.regex):
                        print "%s" % cmlvo.ref
                else:
                    p.print_help()
                    print "You need to provide --platform=<platform name>."
            elif re.match('(?i)updateplatform?',arguments[0]):
                if options.platform:
                    print "Updating platform on the following cml(s):"
                    for cmlvo in s.updateCMLPlatform(options.id,options.platform,options.regex):
                        print "%s" % cmlvo.ref
                else:
                    p.print_help()
                    print "You need to provide --platform=<platform name>."
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
        print "cml cmd is exiting because it couldn't authenticate the user."
    except (KeyboardInterrupt):
        print "cml cmd is exiting because it received a Ctrl-C sequence from the keyboard."
    except OSError,args:
        print "OS had problems performing system call: %s" % args
    except SALib.RegExInvalid,args:
        print "Regular Expression is invalid the message was: %s" % args
    except SALib.NullSearchValue:
        print "Specified a blank value or space."
    except SALib.PlatformMismatchException,args:
        print "AppConfiguration most likely has a platform mismatch with CML item(s):\n%s" % '\n'.join(args.__str__().split('\n')[0:4])
