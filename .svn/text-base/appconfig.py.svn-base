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

def printConfigurableItems(salib,configRefs,parameter,selector,regex,match=True):
    if selector == 'name':
        s = 0
    elif selector == 'value':
        s = 1
    elif selector == 'all':
        s = 2
    for configItem in salib.findConfigurationParameter(configRefs,parameter,s,regex,match):
        print "%s" % configItem.configVO.ref
        for foundValuesetKey in configItem.foundValuesetKeys:
            print "%s: %s" % (foundValuesetKey,configItem.configVO.valueset[foundValuesetKey])
        for appInstance in configItem.instances:
            appInstanceVO = configItem.configVO.instances[appInstance.index]
            print "%s" % appInstanceVO.ref
            for foundValuesetKey in appInstance.foundValuesetKeys:
                print "%s: %s" % (foundValuesetKey,appInstanceVO.valueset[foundValuesetKey])
        print

def main():
    p = sacliutil.standardOptions("appconfig --id=<identifier> [--<modifier options>] [ <action> ]")
    p.add_option('--id', help="Specify identifier for appconfig.")
    p.add_option('--server', help="Specify server pattern for appconfig.")
    p.add_option('--name', help="Specifies name valueset of the appconfig.")
    p.add_option('--value', help="Specifies value valueset of the appconfig.")
    p.add_option('--matchstr', help="search string for replacement by --value.")
    p.add_option('--clonename', help="Specifies appconfig clone name.")
    p.add_option('--customer', help="Specify servers by customer name.")
    p.add_option('--facility', help="Specifies servers by facility name.")
    p.add_option('--platform', help="Specify platform by id, name, or pattern.")
    p.add_option('--scope',default='all',help="specify either appconfig,customer,facility,devicegroup,server,or all")
    p.add_option('--show', action="store_true",help="Show before and after valueset changes.")
    p.add_option('--dryrun', action="store_true",help="Do a dry run of valuereplace.")
    (options, arguments) = p.parse_args()
    s = sacliutil.getSALib(options.username,options.password,options.authfile)

    if options.debug:
        s.setDebug(1)
    if options.id or options.server or options.facility or options.customer:
        action = ['list','namesearch','valuesearch','valuereplace','valueset','clone','addplatform','updateplatform']
        if arguments:
            if re.match('[Ll]ist$',arguments[0]):
                for i in s.getConfigurationRefs(options.id,options.regex):
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
            elif re.match('[Nn]amesearch',arguments[0]):
                if options.name:
                    if options.id:
                        configurationRefs = s.getConfigurationRefs(options.id,options.regex)
                        printConfigurableItems(s,configurationRefs,options.name,'name',options.regex)
                    elif options.server:
                        serverRefs = s.getServerRefs(options.server,options.regex)
                        printConfigurableItems(s,serverRefs,options.name,'name',options.regex)
                    elif options.customer:
                        serverRefs = s.getServerRefsByCustomer(options.customer,options.regex)
                        printConfigurableItems(s,serverRefs,options.name,'name',options.regex)
                    elif options.facility:
                        serverRefs = s.getServerRefsByFacility(options.facility,options.regex)
                        printConfigurableItems(s,serverRefs,options.name,'name',options.regex)
                    else:
                        p.print_help()
                        print "Please provide an id, server, customer, or facility option with --name"
                else:
                    p.print_help()
                    print "Please provide --name and either --id, --server, --customer,or --facility with namesearch action"
            elif re.match('[Vv]aluesearch',arguments[0]):
                if options.value:
                    if options.id:
                        configurationRefs = s.getConfigurationRefs(options.id,options.regex)
                        printConfigurableItems(s,configurationRefs,options.value,'value',options.regex)
                    elif options.server:
                        serverRefs = s.getServerRefs(options.server,options.regex)
                        printConfigurableItems(s,serverRefs,options.value,'value',options.regex)
                    elif options.customer:
                        serverRefs = s.getServerRefsByCustomer(options.customer,options.regex)
                        printConfigurableItems(s,serverRefs,options.value,'value',options.regex)
                    elif options.facility:
                        serverRefs = s.getServerRefsByFacility(options.facility,options.regex)
                        printConfigurableItems(s,serverRefs,options.value,'value',options.regex)
                else:
                    p.print_help()
                    print "Please provide --value and either --id, --server, --customer,or --facility with valuesearch action"
            elif re.match('[Vv]aluereplace',arguments[0]):
                if (options.name or options.matchstr) and options.value:
                    if options.id:
                        configurationRefs = s.getConfigurationRefs(options.id,options.regex)
                        if options.name:
                            configGenerator = s.findConfigurationParameter(configurationRefs,options.name,0,options.regex)
                        elif options.matchstr:
                            configGenerator = s.findConfigurationParameter(configurationRefs,options.matchstr,1,options.regex,False)
                    elif options.server:
                        serverRefs = s.getServerRefs(options.server,options.regex)
                        if options.name:
                            configGenerator = s.findConfigurationParameter(serverRefs,options.name,0,options.regex)
                        elif options.matchstr:
                            configGenerator = s.findConfigurationParameter(serverRefs,options.matchstr,1,options.regex,False)
                    elif options.customer:
                        serverRefs = s.getServerRefsByCustomer(options.customer,options.regex)
                        if options.name:
                            configGenerator = s.findConfigurationParameter(serverRefs,options.name,0,options.regex)
                        elif options.matchstr:
                            configGenerator = s.findConfigurationParameter(serverRefs,options.matchstr,1,options.regex,False)
                    elif options.facility:
                        serverRefs = s.getServerRefsByFacility(options.facility,options.regex)
                        if options.name:
                            configGenerator = s.findConfigurationParameter(serverRefs,options.name,0,options.regex)
                        elif options.matchstr:
                            configGenerator = s.findConfigurationParameter(serverRefs,options.matchstr,1,options.regex,False)
                    if options.dryrun:
                        if options.name:
                            for c in configGenerator:
                                for key in c.foundValuesetKeys:
                                    print "%s (Will NOT modify):" % c.configVO.ref
                                    print "BEFORE: %s = %s" % (key, c.configVO.valueset[key])
                                    print "AFTER: %s = %s\n" % (key, options.value)
                                for instance in c.instances:
                                    print "%s (Will NOT modify):" % c.configVO.instances[instance.index].ref
                                    for key in instance.foundValuesetKeys:
                                        print "BEFORE: %s = %s" % (key,c.configVO.instances[instance.index].valueset[key])
                                        print "AFTER: %s = %s\n" % (key,options.value)
                        elif options.matchstr:
                            for c in configGenerator:
                                for key in c.foundValuesetKeys:
                                    print "%s (Will NOT modify):" % c.configVO.ref
                                    print "BEFORE: %s = %s" % (key, c.configVO.valueset[key])
                                    print "AFTER: %s = %s\n" % (key,re.sub(options.matchstr, options.value, c.configVO.valueset[key])) 
                                for instance in c.instances:
                                    print "%s (Will NOT modify):" % c.configVO.instances[instance.index].ref
                                    for key in instance.foundValuesetKeys:
                                        print "BEFORE: %s = %s" % (key,c.configVO.instances[instance.index].valueset[key])
                                        print "AFTER: %s = %s\n" % (key,re.sub(options.matchstr, options.value, c.configVO.instances[instance.index].valueset[key]))
                    else:
                        if options.name:
                            replaceConfigGen = s.replaceConfigurationValue(configGenerator,options.value,options.scope,options.show,False,None)
                        elif options.matchstr:
                            replaceConfigGen = s.replaceConfigurationValue(configGenerator,options.value,options.scope,options.show,True,None)
                        for twistConfigItem in replaceConfigGen:
                            print "%s: Modified" % twistConfigItem.ref
                            if options.show:
                                print
                else:
                    p.print_help()
                    print "Please provide both --name=<name in valueset> and --value=<replacement value> with valuereplace action."
            elif re.match('[Vv]aluesets?',arguments[0]):
                if options.id:
                    configurationRefs = s.getConfigurationRefs(options.id,options.regex)
                    printConfigurableItems(s,configurationRefs,None,'all',options.regex)
                elif options.server:
                    serverRefs = s.getServerRefs(options.server,options.regex)
                    printConfigurableItems(s,serverRefs,None,'all',options.regex)
                elif options.customer:
                    serverRefs = s.getServerRefsByCustomer(options.customer,options.regex)
                    printConfigurableItems(s,serverRefs,None,'all',options.regex)
                elif options.facility:
                    serverRefs = s.getServerRefsByFacility(options.facility,options.regex)
                    printConfigurableItems(s,serverRefs,None,'all',options.regex)
            elif re.match('[Cc]lone',arguments[0]):
                if options.clonename:
                    configRef = s.cloneConfigurationRef(options.id,options.clonename)
                    if s.isHPSA9x():
                        print "created %s|ConfigurationRef:%d" % (sacliutil.printObjectPath(s,[configRef]),configRef.id)
                    else:
                        print "%s|%s" % (configRef,sacliutil.printObjectID(configRef))
            elif re.match('(?i)addplatform?',arguments[0]):
                if options.platform:
                    print "Adding platform on the following configurationVO(s):"
                    for configvo in s.addConfigurationPlatform(options.id,options.platform,options.regex):
                        print "%s" % configvo.ref
                else:
                    p.print_help()
                    print "You need to provide --platform=<platform name>."
            elif re.match('(?i)updateplatform?',arguments[0]):
                if options.platform:
                    print "Updating platform on the following configurationVO(s):"
                    for configvo in s.updateConfigurationPlatform(options.id,options.platform,options.regex):
                        print "%s" % configvo.ref
                else:
                    p.print_help()
                    print "You need to provide --platform=<platform name>."
            else:
                p.print_help()
                print "Provide an action: %s" % sacliutil.getActionList(action)
        else:
            p.print_help()
            print "Provide an action: %s" % sacliutil.getActionList(action)
    else:
        p.print_help()
    
if __name__ == '__main__':
    try:
        main()
    except (SALib.AuthenticationFailed):
        print "appconfig cmd is exiting because it couldn't authenticate the user."
    except (KeyboardInterrupt):
        print "appconfig cmd is exiting because it received a Ctrl-C sequence from the keyboard."
    except OSError,args:
        print "OS had problems performing system call: %s" % args
    except SALib.RegExInvalid,args:
        print "Regular Expression is invalid the message was: %s" % args
    except ValueError,args:
        print "Incorrect value for a option given: %s" % args
    except SALib.PlatformMismatchException,args:
        print "CML items attached to this Appconfig probably has platform mismatch with the AppConfiguration:\n%s" % '\n'.join(args.__str__().split('\n')[0:4])
