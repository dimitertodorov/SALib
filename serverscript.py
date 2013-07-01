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

class bothSgroupAndServer(Exception):
    pass

def main():
    p = sacliutil.standardOptions("serverscript --id=<identifier> [--<modifier options>] [ <action> ]")
    p.add_option('--id', help="Specify server script name, id, or folder path and server script name")
    p.add_option('--server', help="Specify server name or id")
    p.add_option('--servergroup', help="Specify server group by id or path.")
    p.add_option('--spolicy', help="Specify servers by software policy associations.")
    p.add_option('--customer', help="Specify servers by customer associations.")
    p.add_option('--facility', help="Specify servers by facility associations.")
    p.add_option('--file', help="Specify script filename.")
    p.add_option('--folder', help="Specify folder by id or path that script will be stored in.")
    p.add_option('--type', help="Specify the script extension sh, ps1, bat, or vbs (unix shell, powershell, batch, or visual basic script respectively.)")
    p.add_option('--args', default='', help="Specify arguments that need to be passed to the script.")
    p.add_option('--timeout', default='300', help="Specify timeout for the server script. Default is 300 seconds")
    p.add_option('--scriptname', default='', help="Use this as name instead of the filename for the server script. Default is to use the filename for the server script name.")
    p.add_option('--description', default='', help="Use given description instead of the filename for the server script. Default is to set filename for description.")
    p.add_option('--versionlabel', default='', help="Specify version label for the server script.")
    p.add_option('--nosuperuser',default=True, action="store_false",help="Specify whether this script run as a super user or not. Default is set to True.")
    p.add_option('--email',default=False,action="store_true",help="Email using SA account information. Default is set to False")
    p.add_option('--noserverchange',default=True, action="store_false",help="Specify whether this script can make changes to the server or not. Default is set to True")
    (options,arguments) = p.parse_args()
    s = sacliutil.getSALib(options.username,options.password,options.authfile)

    if options.debug:
        s.setDebug(1)
    if options.id:
        action = ['info','list','run']
        if arguments:
            if re.match('[Ii]nfo',arguments[0]):
                for i in s.getServerScriptRefs(options.id,options.regex):
                    print "Server Script: %s" % i.name
                    sacliutil.print_serverscriptinfo(s,'s.getServerScriptInfo',i)
                    folderdict = s.getServerScriptInfo(i)
                    print "location: %s" % s.getObjectPath( [ folderdict['folder'] ])
                    print "source: \n%s" % s.showServerScriptSource(i)
            elif re.match('(?i)list?',arguments[0]):
                serverScriptRefs = s.getServerScriptRefs(options.id,options.regex)
                for i in serverScriptRefs:
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
            elif re.match('(?i)^run$',arguments[0]):
                if options.id and (options.server or options.servergroup or options.spolicy or options.customer or options.facility or options.sgmembers):
                    jobId = None
                    if options.server and not (options.servergroup or options.spolicy or options.customer or options.facility):
                        serverRefs = s.getServerRefs(options.server,options.regex)
                        jobId = s.runServerScript(options.id,serverRefs,options.args,None,string.atoi(options.timeout),options.email,options.regex)
                    elif options.spolicy and not (options.server or options.servergroup or options.customer or options.facility):
                        serverRefs = []
                        for spolicy,serverlist in s.getServerRefsBySoftwarePolicy(options.spolicy,options.regex).iteritems():
                            serverRefs = serverRefs + serverlist
                        jobId = s.runServerScript(options.id,serverRefs,options.args,None,string.atoi(options.timeout),options.email,options.regex)
                    elif options.servergroup and not (options.server or options.spolicy or options.customer or options.facility):
                        deviceGroupRefs = s.getDeviceGroupRefs(options.servergroup,options.regex)
                        jobId = s.runServerScript(options.id,deviceGroupRefs,options.args,None,string.atoi(options.timeout),options.email,options.regex)
                    elif options.customer and not (options.server or options.servergroup or options.spolicy or options.facility):
                        serverRefs = s.getServerRefsByCustomer(options.customer,options.regex)
                        jobId = s.runServerScript(options.id,serverRefs,options.args,None,string.atoi(options.timeout),options.email,options.regex)
                    elif options.facility and not (options.server or options.servergroup or options.spolicy or options.customer):
                        serverRefs = s.getServerRefsByFacility(options.facility,options.regex)
                        jobId = s.runServerScript(options.id,serverRefs,options.args,None,string.atoi(options.timeout),options.email,options.regex)
                    else:
                        p.print_help()
                        print "Please provide --id=<Server script> and one of (--server,--servergroup,--spolicy,--customer, or--facility) and --type=<SH,PS1,BAT,VBS> with run action"
                    if jobId:
                        print "JobID: %s" % jobId
                else:
                    p.print_help()
                    print "Please provide --id=<SA Server script> and --server=<Server ID or Name>/--servergroup <servergroup id or name> with run action"
            else:
                p.print_help()
                print "Please provide an action: %s" % sacliutil.getActionList(action)
        else:
            p.print_help()
            print "Please provide an action: %s" % sacliutil.getActionList(action)
    elif options.file:
        action = ['runadhoc','create']
        if arguments:
            if re.match('(?i)^runadhoc$',arguments[0]):
#                if options.servergroup and options.server:
#                    p.print_help()
#                    raise bothSgroupAndServer
                if options.file and (options.server or options.servergroup or options.spolicy or options.customer or options.facility) and options.type:
                    jobId = None
                    if re.match('(?i)sh',options.type):
                        codeType = 'SH'
                    elif re.match('(?i)ps1',options.type):
                        codeType = 'PS1'
                    elif re.match('(?i)bat',options.type):
                        codeType = 'BAT'
                    elif re.match('(?i)vbs',options.type):
                        codeType = 'VBS'
                    else:
                        print "--type %s doesn't match sh, ps1, bat, or vbs" % options.type
                        sys.exit(1)
                    if options.server and not (options.servergroup or options.spolicy or options.customer or options.facility):
                        serverRefs = s.getServerRefs(options.server,options.regex)
                        jobId = s.runAdHocScript(options.file,serverRefs,codeType,options.args,string.atoi(options.timeout),options.email,options.regex)
                    elif options.spolicy and not (options.server or options.servergroup or options.customer or options.facility):
                        serverRefs = []
                        for spolicy,serverlist in s.getServerRefsBySoftwarePolicy(options.spolicy,options.regex).iteritems():
                            serverRefs = serverRefs + serverlist
                        jobId = s.runAdHocScript(options.file,serverRefs,codeType,options.args,string.atoi(options.timeout),options.email,options.regex)
                    elif options.servergroup and not (options.server or options.spolicy or options.customer or options.facility):
                        deviceGroupRefs = s.getDeviceGroupRefs(options.servergroup,options.regex)
                        jobId = s.runAdHocScript(options.file,deviceGroupRefs,codeType,options.args,string.atoi(options.timeout),options.email,options.regex)
                    elif options.customer and not (options.server or options.servergroup or options.spolicy or options.facility):
                        serverRefs = s.getServerRefsByCustomer(options.customer,options.regex)
                        jobId = s.runAdHocScript(options.file,serverRefs,codeType,options.args,string.atoi(options.timeout),options.email,options.regex)
                    elif options.facility and not (options.server or options.servergroup or options.spolicy or options.customer):
                        serverRefs = s.getServerRefsByFacility(options.facility,options.regex)
                        jobId = s.runAdHocScript(options.file,serverRefs,codeType,options.args,string.atoi(options.timeout),options.email,options.regex)
                    else:
                        p.print_help()
                        print "Please provide --id=<Server script> and one of (--server,--servergroup,--spolicy,--customer, or--facility) and --type=<SH,PS1,BAT,VBS> with runadhoc action"
                    if jobId:
                        print "JobID: %s" % jobId
                else:
                    p.print_help()
                    print "Please provide --id=<Server script> and --server=<Server ID or Name>/--servergroup=<Server Group ID or Name> and --type=<SH,PS1,BAT,VBS> with runadhoc action"
            elif re.match('(?i)^create$',arguments[0]):
                if options.file and options.folder and options.type:
                    if re.match('(?i)sh',options.type):
                        codeType = 'SH'
                    elif re.match('(?i)ps1',options.type):
                        codeType = 'PS1'
                    elif re.match('(?i)bat',options.type):
                        codeType = 'BAT'
                    elif re.match('(?i)vbs',options.type):
                        codeType = 'VBS'
                    else:
                        print "--type %s doesn't match sh, ps1, bat, or vbs" % options.type
                        sys.exit(1)
                    print "%s" % s.createServerScript(options.file,
                                                      options.type,
                                                      options.folder,
                                                      options.scriptname,
                                                      options.description,
                                                      options.versionlabel,
                                                      options.superuser,
                                                      options.serverchange)
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
    except SALib.VersionStringConflict,args:
        print "--versionlabel %s already exists" % args
    except SALib.NoTargetsSpecified,args:
        print "command couldn't find --server %s issued. Use server --id '%s' list to see if it is in SA." % (args,args)
    except bothSgroupAndServer:
        print "You cannot specify both --server=<Server ID or Name> and --servergroup=<Server Group ID or Name>"
