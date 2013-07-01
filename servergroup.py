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
    p = sacliutil.standardOptions("servergroup (--id=<device group identifier>|--new=<device group name or path>) [modifiers] <action>")
    p.add_option('--id', help="use with action info,listall,listgroup,remove,list,listregex,addservers,removeservers,listdevice")
    p.add_option('--new', help="")
    p.add_option('--devices', help="")
    p.add_option('--expression', help="")
    p.add_option('--empty',action="store_true",help="")
    (options,arguments) = p.parse_args()
    s = sacliutil.getSALib(options.username,options.password,options.authfile)
    if options.debug:
        s.setDebug(1)
    if options.id:
        action = ['info','listall','listgroup','remove','list','listregex','addservers','removeservers','listdevice']
        if arguments:
            if arguments[0] == 'info':
                print "Server Group Name: %s" % (options.id,)
                sacliutil.print_servergroupinfo(s,'s.getServerGroupInfo',options.id)
            elif re.match('[Ll]istdevices?',arguments[0]):
                for i in s.getServerGroupInfo(options.id)['devices']:
                    print "%s" % i
            elif re.match('[Ll]istgroups?',arguments[0]):
                for i in s.getServerGroupInfo(options.id)['children']:
                    print "%s" % i
            elif re.match('[Rr]emove',arguments[0]):
                s.removeServerGroup(options.id)
            elif re.match('[Aa]ddservers?',arguments[0]):
                if options.devices:
                    s.addServersToServerGroup(options.devices,options.id)
                else:
                    print "ERROR: Need to specify the devices to add with --devices=<server names,>"
                    sys.exit(1)
            elif re.match('[Rr]emoveservers?',arguments[0]):
                if options.devices:
                    s.removeServersFromServerGroup(options.devices,options.id)
                else:
                    print "ERROR: Need to specify the devices to remove with --devices=<server names,>"
                    sys.exit(1)
            elif re.match('[Ll]ist',arguments[0]):
                if re.match('[Ll]istall',arguments[0]):
                    for i in list(s.getServerGroupInfo(options.id)['children']): print "%s" % i
                    for i in list(s.getServerGroupInfo(options.id)['devices']): print "%s" % i
                else:
                    for i in s.getDeviceGroupRefs(options.id):
                        dvcGroupVO = s.callUAPI('device.DeviceGroupService','getDeviceGroupVO',i)
                        print "%s (DeviceGroupRef: %d)" % (re.sub('^Device Groups','',dvcGroupVO.fullName),i.id)
            elif re.match('[Rr]egexlist',arguments[0]):
                for i in s.getDeviceGroupRefs(options.id,True):
                    dvcGroupVO = s.callUAPI('device.DeviceGroupService','getDeviceGroupVO',i)
                    print "%s (DeviceGroupRef: %d)" % (re.sub('^Device Groups','',dvcGroupVO.fullName),i.id)
            else:
                p.print_help()
                print "With --id=<device group identifier> you need to provide an action: %s" % \
                                                                    sacliutil.getActionList(action)
        else:
            p.print_help()
            print "With --id=<device group identifier> you need to provide an action: %s" % \
                                                                sacliutil.getActionList(action)
    elif options.new:
        action = ['create']
        if arguments:
            if re.match('[Cc]reate',arguments[0]):
                if options.devices:
                    if options.expression:
                        print "You can't add device(s) to a dynamic group. Using the expression option implies that this is a dynamic group."
                    else:
                        s.createServerGroup(options.new,options.devices)
                elif options.expression:
                    s.createServerGroup(options.new,isDynamic=True,ruleExpression=options.expression)
                elif options.empty:
                    s.createServerGroup(options.new,dvc_list=[])
                else:
                    p.print_help()
                    print "Please specify --devices,--expression,or --empty to create either a static group, a dynamic group, or an empty server group respectively."
            else:
                p.print_help()
                print "Please provide create action with --new."
        else:
            p.print_help()
            print "With --new=<new device group or device group path> you need to provide an action: %s" % \
                                                                sacliutil.getActionList(action)
    else:
        p.print_help()


if __name__ == '__main__':
    try:
        main()
    except (SALib.AuthenticationFailed):
        print "servergroup cmd is exiting because it couldn't authenticate the user."
    except (KeyboardInterrupt):
        print "servergroup cmd is exiting because it received a Ctrl-C sequence from the keyboard."
    except OSError,args:
        print "OS had problems performing system call: %s" % args
    except SALib.RegExInvalid,args:
        print "Regular Expression is invalid the message was: %s" % args
    except SALib.NoDeviceGroupRefFound,args:
        print "ERROR: Could not find Server Group %s" % dir(args)
    except SALib.MultipleDeviceGroupRefsFound,sgref:
        print "ERROR: Multiple Server Groups matched %s. Specify a specific one." % sgref 
    except SALib.ObjectAlreadyExists:
        print "ERROR: Server Group already exists."

