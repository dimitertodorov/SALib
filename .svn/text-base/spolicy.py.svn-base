#!/opt/opsware/bin/python2

import os
import re
import sre_constants
import string
import sys
import time
import optparse
import SALib
import sacliutil
import getpass

def main():
    p = sacliutil.standardOptions("spolicy --id=<identifier> [--<modifier options>] [ <action> ]")
    p.add_option('--id', help="Specify a identifier which is an Opsware ID, software policy name, or folder path and software policy name.")
    p.add_option('--folderpath', help="Specify a folder path for the software policy refs.")
    p.add_option('--new', help="Specify a new software policy name.")
    p.add_option('--policyitem', help="Use with --policyitem when using the action additems or replaceitems.")
    p.add_option('--order', help="Use with --policyitem and/or action additems or replaceitems to specify the policy item order to add or replace respectively.")
    p.add_option('--folder', help="Use with software policy creation.")
    p.add_option('--platform', help="Use with software policy creation.")
    p.add_option('--server', help="Use with software policy install and uninstall.")
    p.add_option('--servergroup', help="Use with software policy install and uninstall.")
    p.add_option('--sgmembers', help="Use with software policy install and uninstall.")
    p.add_option('--name', help="Use with software policy setca (Set Custom Attribute)")
    p.add_option('--value', help="Use with software policy setca (Set Custom Attribute)")
    p.add_option('--recursive', action="store_true",help="Recursively traverse the folders.")
    p.add_option('--spfilter', help="Specify a software policy name filter.")
    (options,arguments) = p.parse_args()
    s = sacliutil.getSALib(options.username,options.password,options.authfile)

    if options.debug:
        s.setDebug(1)
    if options.id:
        action = ['list','listitems','additems','replaceitems','deleteitems','addplatform','updateplatform','create','install','uninstall','getca','setca','serverlist','remediate']
        if arguments:
            if re.match('[Ll]ist$',arguments[0]):
                objPaths = []
                if options.regex:
                    softwarePolicyRefs = s.getSoftwarePolicyRefs(options.id,True)
                else:
                    softwarePolicyRefs = s.getSoftwarePolicyRefs(options.id)
                for i in softwarePolicyRefs:
                    try:
                        print "%s|%s" % (sacliutil.printObjectPath(s,[i]),sacliutil.printObjectID(i))
                    except SALib.AuthorizationDeniedException:
                        print "!!!%s is INACCESSIBLE!!!" % i
                        continue
                    except SALib.NotInFolder,i:
                        print "!!!%s is INACCESSIBLE!!!" % i
                        continue
            elif re.match('[Ss]erverlist$',arguments[0]):
                for spolicy,serverlist in s.getServerRefsBySoftwarePolicy(options.id,options.regex).iteritems():
                    print "%s" % spolicy
                    for server in serverlist:
                        print "%s" % server
                    print
            elif re.match('[Aa]dditems?',arguments[0]):
                try:
                    if options.policyitem:
                        policyItemRefs = sacliutil.createPolicyItemList(s,options.policyitem)
                        print "%s" % policyItemRefs
                        if options.order:
                            print "%s has been updated." % s.addSoftwarePolicyItem(options.id,policyItemRefs,options.order).ref
                        else:
                            print "%s has been updated." % s.addSoftwarePolicyItem(options.id,policyItemRefs).ref
                    else:
                        print "With --id and action additems you need to provide --policyitem"
                except SALib.DuplicatePolicyItemFound,args:
                    print "The policyitem %s already exist in the software policy." % args
            elif re.match('[Rr]eplaceitems?',arguments[0]):
                if options.policyitem:
                    if options.order:
                        try:
                            policyItemRef = sacliutil.createPolicyItemList(s,options.policyitem)
                            print "%s" % options.policyitem
                            print "%s" % policyItemRef
                            if len(policyItemRef) > 1:
                                print "You need to provide only one --policyitem because you can only replace items one at a time." 
                                sys.exit()
                            sref = s.replaceSoftwarePolicyItembyPosition(options.id,policyItemRef[0],options.order).ref
                            print "%s has been updated" % sref
                        except SALib.NoObjectRefFound,args:
                            print "Couldn't find policy item %s to replace" % args
                        except SALib.NotSoftwarePolicyItem,args:
                            print "The referenced item %s can't be added to a software policy." % args
                        except IndexError,args:
                            print "%s is an incorrect SA Object type. Check the issued --policyitem args for the correct type." % \
                                        options.policyitem
                    else:
                        p.print_help()
                        print "You need to specify the order of the software policy item to replace using --order"
                else:
                    p.print_help()
                    print "You need to specify the policy item and order of the policy item within the software policy like --policyitem RPMRef:10001 --order 3"
            elif re.match('[Dd]eleteitems?',arguments[0]):
                if options.order:
                    print "%s has been updated" % s.deleteSoftwarePolicyItembyPosition(options.id,options.order).ref
            elif re.match('[Ll]istitems?',arguments[0]):
                for spolicyRef in s.getSoftwarePolicyRefs(options.id):
                    try:
                        print "software policy:"
                        print "%s|%s" % (sacliutil.printObjectPath(s,[spolicyRef]),sacliutil.printObjectID(spolicyRef))
                        print "items:"
                        listSPItems = s.listSoftwarePolicyItems(spolicyRef.id)
                        seqNumber = 1
                        for item in listSPItems[spolicyRef]:
                            itemRef = re.sub('(.*)(\()([A-Za-z]*\:[0-9]*[^)])(\).*)','\\3',"%s" % item)
                            policyItem = "%s|%s" % (itemRef,sacliutil.printObjectPath(s,[item]))
                            print "%d|%s" % (seqNumber,policyItem)
                            seqNumber += 1
                        print
                    except SALib.AuthorizationDeniedException:
                        print "!!!%s is INACCESSIBLE!!!" % i
                        continue
                    except SALib.NotInFolder,i:
                        print "!!!%s is INACCESSIBLE!!!" % i
                        continue
            elif re.match('[Ii]nstall', arguments[0]):
                if options.server and not (options.servergroup or options.sgmembers):
                    jobId = s.installSoftwarePolicyOnServers(options.server,options.id,options.regex)
                    print "%s" % jobId
                elif options.servergroup and not (options.server or options.sgmembers):
                    jobId = s.installSoftwarePolicyOnDeviceGroups(options.servergroup,options.id,options.regex)
                    print "%s" % jobId
                elif options.sgmembers and not (options.server or options.servergroup):
                    jobId = s.installSoftwarePolicyViaServerGroupMembers(options.sgmembers,options.id,options.regex)
                    print "%s" % jobId
                else:
                    p.print_help()
                    print "You need to either provide --server=<server names>, --servergroup=<server group names>, --sglist, and  with action install."
            elif re.match('[Uu]ninstall', arguments[0]):
                if options.server and not options.servergroup and not options.sgmembers:
                    jobId = s.uninstallSoftwarePolicyOnServers(options.server,options.id,options.regex)
                    print "%s" % jobId
                elif options.servergroup and not options.server and not options.sgmembers:
                    jobId = s.uninstallSoftwarePolicyOnDeviceGroups(options.servergroup,options.id,options.regex)
                    print "%s" % jobId
                elif options.sgmembers and not options.server and not options.servergroup:
                    jobId = s.uninstallSoftwarePolicyViaServerGroupMembers(options.sgmembers,options.id,options.regex)
                    print "%s" % jobId
                else:
                    p.print_help()
                    print "You need to either provide --server=<server names>, --servergroup=<server group names>, or --sglist with action uninstall."
            elif re.match('[Rr]emediate', arguments[0]):
                    serverRefs = []
                    for spolicy,serverList in s.getServerRefsBySoftwarePolicy(options.id,options.regex).iteritems():
                        serverRefs = serverRefs + serverList
                    spolicyRefs = s.getSoftwarePolicyRefs(options.id,options.regex)
                    jobId = s.installSoftwarePolicy(serverRefs,spolicyRefs)
                    print "%s" % jobId
            elif re.match('(?i)addplatform?',arguments[0]):
                if options.platform:
                    print "Adding platform on the following software policies:"
                    for spolicyvo in s.addSoftwarePolicyPlatform(options.id,options.platform,options.regex):
                        print "%s" % spolicyvo.ref
                else:
                    p.print_help()
                    print "You need to provide --platform=<platform name>."
            elif re.match('(?i)updateplatform?',arguments[0]):
                if options.platform:
                    print "Updating platform on the following software policies:"
                    for spolicyvo in s.updateSoftwarePolicyPlatform(options.id,options.platform,options.regex):
                        print "%s" % spolicyvo.ref
                else:
                    p.print_help()
                    print "You need to provide --platform=<platform name>."
            elif re.match('(?i)getca?',arguments[0]):
                spolicycas = s.getCustomAttributesOnSoftwarePolicy(options.id,options.regex)
                for spolicy in spolicycas.keys():
                    print "%s|%s" % (sacliutil.printObjectPath(s,[spolicy]),sacliutil.printObjectID(spolicy))
                    for ca in spolicycas[spolicy].keys():
                        print "%s : %s" % (ca,spolicycas[spolicy][ca])
                    print
            elif re.match('(?i)setca?',arguments[0]):
                if options.name and options.value:
                    spolicylist = s.setCustomAttributeOnSoftwarePolicy(options.id,options.name,options.value,options.regex)
                    print "Updated software policy:"
                    for spolicy in spolicylist:
                        print "%s|%s" % (sacliutil.printObjectPath(s,[spolicy]),sacliutil.printObjectID(spolicy))
                    print
                else:
                    p.print_help()
                    print "You need to either provide --name=<name> and --value=value with action setca."
            elif re.match('(?i)remca?',arguments[0]):
                if options.name:
                    print "Updated software policy:"
                    for spolicy in s.removeCustomAttributeOnSoftwarePolicy(options.id,options.name,options.regex):
                        print "%s|%s" % (sacliutil.printObjectPath(s,[spolicy]),sacliutil.printObjectID(spolicy))
                    print
                else:
                    p.print_help()
                    print "You need to either --name=<name> with action remca to remove custom atttributes."                    
            else:
                p.print_help()
                print "Provide an action: %s" % sacliutil.getActionList(action)
        else:
            p.print_help()
            print "Provide an action: %s" % sacliutil.getActionList(action)
    elif options.new:
        action = ['create']
        if arguments:
            if re.match('[Cc]reate',arguments[0]):
                (folderPath,spolicyName) = os.path.split(options.new)
                if folderPath:
                    folderName = folderPath
                else:
                    if options.folder:
                        folderName = options.folder
                    else:
                        folderName = "/"
                if options.platform:
                    platforms = options.platform
                else:
                    platforms = "OS Independent"
                if options.policyitem:
                    policyItemRefs = sacliutil.createPolicyItemList(s,options.policyitem)
                    spolicyVO = s.createSoftwarePolicy(folderName,spolicyName,platforms,policyItemRefs)
                else:
                    spolicyVO = s.createSoftwarePolicy(folderName,spolicyName,options.platform)
                print "created %s|%s" % (sacliutil.printObjectPath(s,[spolicyVO.ref]),sacliutil.printObjectID(spolicyVO.ref))
        else:
            p.print_help()
            print "Specify --new=[<new software policy>|<folder path to new software policy>] and optionally --platform=<platform name> and --folder=<folder path> with action create"
            print "If you leave off --platform and --folder the defaults are OS independent and / respectively."
    elif options.folderpath:
        action = ['list','setca','getca','remca']
        if arguments:
            if options.regex:
                regex = True
            else:
                regex = False
            if re.match('(?i)lists?$',arguments[0]):
                if options.spfilter:
                    s.printFolderObj(options.folderpath,options.recursive,'SoftwarePolicyRef',regex,options.spfilter)
                else:
                    s.printFolderObj(options.folderpath,options.recursive,'SoftwarePolicyRef',regex)
            elif re.match('(?i)getca$',arguments[0]):
                for i in s.getFolderObj(options.folderpath,options.recursive,'SoftwarePolicyRef',regex,options.spfilter):
                    spolicycas = s.getCustomAttributesOnSoftwarePolicy(i.id,options.regex)
                    for spolicy in spolicycas.keys():
                        print "%s|%s" % (sacliutil.printObjectPath(s,[spolicy]),sacliutil.printObjectID(spolicy))
                        for ca in spolicycas[spolicy].keys():
                            print "%s : %s" % (ca,spolicycas[spolicy][ca])
                        print
            elif re.match('(?i)setca$',arguments[0]):
                if options.name and options.value:
                    print "Updated software policy:"
                    for i in s.getFolderObj(options.folderpath,options.recursive,'SoftwarePolicyRef',regex,options.spfilter):
                        spolicylist = s.setCustomAttributeOnSoftwarePolicy(i.id,options.name,options.value,options.regex)
                        for spolicy in spolicylist:
                            print "%s|%s" % (sacliutil.printObjectPath(s,[spolicy]),sacliutil.printObjectID(spolicy))
                else:
                    p.print_help()
                    print "You need to either provide --name=<name> and --value=value with action setca."
            elif re.match('(?i)remca$',arguments[0]):
                if options.name:
                    print "Updated software policy:"
                    for i in s.getFolderObj(options.folderpath,options.recursive,'SoftwarePolicyRef',regex,options.spfilter):
                        for spolicy in s.removeCustomAttributeOnSoftwarePolicy(i.id,options.name,options.regex):
                            print "%s|%s" % (sacliutil.printObjectPath(s,[spolicy]),sacliutil.printObjectID(spolicy))
                else:
                    p.print_help()
                    print "You need to either --name=<name> with action remca to remove custom attributes."                
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
        print "spolicy cmd is exiting because it couldn't authenticate the user."
    except (KeyboardInterrupt):
        print "spolicy cmd is exiting because it received a Ctrl-C sequence from the keyboard."
    except OSError,args:
        print "OS had problems performing system call: %s" % args
    except SALib.RegExInvalid,args:
        print "Regular Expression is invalid the message was: %s" % args
    except SALib.InvalidSearchExpression,args:
        print "The Regular Expression you're using in one of your options aren't valid or the given expression isn't finding any SA Objects."
    except SALib.AuthorizationDeniedException,args:
        print "Either you don't have:"
        print "1. Permissions to run the action."
        print "2. You don't have read, write, or execute permission in the folder the software policy is in."
        print "3. You don't have read or write access to server you trying to install a software policy on."
        print "Here is the message given: %s" % args.message
    except SALib.PlatformMismatchException,args:
        print "Policy Item doesn't match Platform for the software policy: %s" % args
    except SALib.NotSoftwarePolicyItem,args:
        print "%s is not a software policy item" % args
    except SALib.DuplicatePolicyItemFound,args:
        print "%s item is already in the software policy." % args
    except IndexError,args:
        print "%s is an incorrect SA Object type. Check the issued --policyitem args for the correct type." % args  
    except SALib.UnknownPolicyItemType,args:
        print "Either policy item type doesn't exist or the format <policy item type>:<id> (i.e. RPMRef:10001) was not correctly specified."
    except SALib.NoObjectRefFound,args:
        print "Couldn't find the Object %s. Check to make sure the folder path is correct." % args
    except sre_constants.error, args:
        print "The error --> '%s' most likely indicates an invalid regular expression. Check the regex expression for --folderpath and/or --spfilter." % args
    except SALib.NoDeviceGroupRefFound, args:
        print "Couldn't find the specified server group %s." % args
    except SALib.MultipleDeviceGroupRefsFound:
        print "You need to specify a single server group with the given options."