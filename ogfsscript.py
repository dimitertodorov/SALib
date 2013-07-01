#!/opt/opsware/bin/python2

import os
import re
import string
import sys
import time
import optparse
import SALib
import sacliutil
import shlex
import subprocess
import getpass

def main():
    p = sacliutil.standardOptions("")
    p.add_option('--id', help="Specify ID or OGFS Script name.")
    p.add_option('--notification', action="store_true",help="Emails notification to the user.")
    p.add_option('--args', help="Arguments to pass to the OGFS Script.", default="")
    p.add_option('--exe', help="Interpreter or shell to use, by default /bin/bash", default="/bin/bash")
    p.add_option('--workingdir', help="Working directory of the OGFS Script.")
    p.add_option('--version', help="Version Label for OGFS Script.")
    (options,arguments) = p.parse_args()
    s = sacliutil.getSALib(options.username,options.password,options.authfile)

    if options.debug:
        s.setDebug(1)
    if options.id:
        action = ['wayrun','list','run','print']
        if arguments:
            if re.match('[Ww]ayrun',arguments[0]):
                if options.args:
                    args = options.args
                else:
                    args = ''
                jobid = s.runOGFSScript(options.id,args,options.notification,options.workingdir)
                print "%s" % jobid
            elif re.match('[Rr]un',arguments[0]):
                #result = subprocess.Popen(args=s.getOGFSScriptSource(options.id,options.version),shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                ogfs_ref = s.getOGFSScriptRefs(options.id, options.regex)
                if len(ogfs_ref) > 1:
                    raise SALib.MultipleOGFSScriptFound,ogfs_ref
                script_path = "/tmp/%s-ogfsscript-%s" % (s._SALib__username, ogfs_ref[0].id)
                fd = open( script_path, "w+")
                fd.write(s.getOGFSScriptSource(options.id,options.version))
                fd.close()
                os.chmod( script_path, 0700 )
                args = [ ]
                if options.exe:
                    args.append(options.exe)
                args = args + [ script_path ] + shlex.split(options.args)
                ret = subprocess.call(args)
                sys.exit(ret)
                #print "%s" % result.stdout.read()
                #stdErr = result.stderr.read()
                #if stdErr:
                #    print "%s" % stdErr
            elif re.match('[p]rint',arguments[0]):
                print "%s" % s.getOGFSScriptSource(options.id,options.version)
            elif re.match('[Ll]ist',arguments[0]):
                OGFSScriptRefs = s.getOGFSScriptRefs(options.id,options.regex)
                for i in OGFSScriptRefs:
                    try:
                        pathDict = s.getObjectPath([ i ],False) 
                        (parentPath,SP) = os.path.split(pathDict[i])
                        if parentPath == "/":
                            print "%s%s" % (parentPath,i)
                        else:
                            print "%s/%s" % (parentPath,i)
                    except SALib.AuthorizationDeniedException:
                        print "!!!%s is INACCESSIBLE!!!" % i
                        continue
                    except SALib.NotInFolderException:
                        print "!!!%s is INACCESSIBLE!!!" % i
                        continue
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
    except SALib.MultipleOGFSScriptFound,args:
        print "Multiple OGFS scripts found: %s" % args
