#!/usr/bin/env python2

import os
import re
import string
import sys
import time
import optparse
import SALib
import getpass

#
# Object options list
#
# object_list = [   ['server','s','Provide ID or Name of Server'],['spolicy','p','Provide ID or Path and Software Policy name'],\
#       ['servergroup','g','Provide ID or Path and Server Group name'],['serverscript','t','Server Script'],\
#       ['ogfsscript','o','Provide ID or OGFS Script name'],['snapshot','n','Provide ID or Snapshot name'],\
#       ['appconfig','a','Provide ID or Appconfiguration name'],['audit','u','Provide ID or Audit name'],\
#       ['folder','f','Provide ID or Folder Path/Name'] ]
object_list = { 'server':['server','s','Provide ID or Name of Server.'],\
        'servergroup':['servergroup','g','Provide ID or Path or Server Group name.'],\
        'appconfig':['appconfig','a','Provide ID or Path or AppConfiguration name.'],\
        'folder':['folder','f','Provide ID or Folder Path/Name.'],\
        'platform':['platform','p','Provide ID or Platform Name.'],\
        'username':['username','n','Provide username.'],\
        'apx':['apx','x','Provide ID or APX Name.'],\
        'customfield':['customfield','c','Provide custom field name.'],\
        'job':['job','j','Provide Job ID.'],\
        'serverscript':['serverscript','t','Provide ID or Server Script Name.'],\
        'package':['package','k','Provide ID or Unit Name.'],\
        'usergroup':['usergroup','u','Provide ID or UserGroup Name.'],\
        'searchobj':['searchobj','f','Provide search object string.'],\
        'spolicy':['spolicy','p','Provide ID or Path and Software Policy name.'] }
def help():
    print "In usage call..."

def _print_dict(s,method_call,dict_obj):
    # dict_obj = "%s" % eval(method_call)(dict_obj)
    # dict_obj = re.sub('[{}]','',dict_obj)
    # print "%s" % dict_obj
    dict_obj = eval(method_call)(dict_obj)
    dict_obj_list = dict_obj.keys()
    dict_obj_list.sort()
    for j in dict_obj_list:
        if type(dict_obj[j]) == list or type(dict_obj[j]) == tuple:
            print "%s:" % j
            for z in dict_obj[j]:
                print "%s" % z.name
        else:
            print "%s: %s" % (j,dict_obj[j])

def print_serverinfo(s,salib_call,server):
    _print_dict(s,salib_call,server)

def print_servergroupinfo(s,salib_call,devicegroup):
    _print_dict(s,salib_call,devicegroup)

def print_folderinfo(s,salib_call,folder):
    _print_dict(s,salib_call,folder)

def print_serverscriptinfo(s,salib_call,serverscript):
    _print_dict(s,salib_call,serverscript)

def option_usage(message,action):
    print "%s %s" % (message,action)

def printObjectPath(s,ObjectRef):
    if len(ObjectRef) > 1:
        SALib.MultipleObjectRefsFound,ObjectRef
    pathDict = s.getObjectPath(ObjectRef,False)
    return "%s" % pathDict[ObjectRef[0]]

def createPolicyItemList(s,policyItemString):
    policyItemRefs = []
    itemList = re.split('[,]',policyItemString)
    for item in itemList:
        if re.search('[/]',item):
            policyItemRefs += s.getFolderRefs(item,regex=False,listall=True)
        elif re.search('[:]',item):
            (ref,id) = re.split('[:]',re.sub('(.*\()([A-Za-z]+\:[0-9]*[^)])(\\).*)','\\2',item))
            refInstance = eval("SALib.%s(%s)" % (ref,id))
            if isinstance(refInstance,SALib.unitRefs):
                unitItems = s.getUnitRefs(id) 
                policyItemRefs += unitItems
            else:
                getObjectRefMethod = eval("s.get%ss" % ref)
                objectItems = getObjectRefMethod(id)
                policyItemRefs += objectItems
        else:
            raise SALib.UnknownPolicyItemType,item  
    return policyItemRefs

def main():
    p = optparse.OptionParser(  usage="sacli --<SA Object option> [--<modifier options>] [ <action> ]",\
                                version="sacli 3.0",\
                                description="Command line interface into HPSA",\
                                conflict_handler="resolve"  )
    object_list_keys = object_list.keys()
    object_list_keys.sort()
    if 'HOMEDIR' in os.environ.keys():
        homedir = os.environ['HOMEDIR']
    elif 'HOME' in os.environ.keys():
        homedir = os.environ['HOME']
    else:
        homedir = '.'
    for i in object_list_keys:
        p.add_option('--%s' % object_list[i][0], '-%s' % object_list[i][1], help="%s" % object_list[i][2])
    p.add_option('--days', '-d', help="Use with --server or -s. Number of days to go back for server history.")
    p.add_option('--weeks', '-w', help="Use with --server or -s. Number of weeks to go back server history.")
    p.add_option('--dvcid', action="store_true",help="Use with --server or -s. Prints out the server id or mid.")
    p.add_option('--recursive', action="store_true",help="Use with --folder or --servergroup. Prints out all child folders or servergroup")
    p.add_option('--listsearchtypes', action="store_true",help="Prints out all search types.")
    p.add_option('--listpkgtypes', action="store_true",help="Prints out all package types.")
    p.add_option('--debug', action="store_true",help="Prints out debug info.")
    p.add_option('--regex', action="store_true",help="Interpret object string as a regular expression.")
    p.add_option('--filtersyntax', action="store_true",help="Prints filter syntax expression.")
    p.add_option('--applytoparent', action="store_true",help="Use with --folder. Applies permissions to parent folders.")
    p.add_option('--attribute', help="Use with --searchobj and action getoperator.")
    p.add_option('--expression', help="Use with --searchobj and action search")
    p.add_option('--empty', action="store_true", help="Use with --servergroup and action create to create an empty server group.")
    p.add_option('--outfile', help="Use with --package and action download")
    p.add_option('--pkgtype', help="Use with --package when using the action upload. Use --listpkgtypes to get list of valid types.")
    p.add_option('--policyitem', help="Use with --spolicy when using the action additems or replaceitems.")
    p.add_option('--order', help="Use with --spolicy when using the action additems or replaceitems to specify the policy item order to add or replace another policy item.")
    p.add_option('--name', help="Use with --appconfig and --name with action namesearch and replacevalue.")
    p.add_option('--perm', help="Use with --folder. Set permissions on folders.")
#   p.add_option('--username', help="Use with --usergroup.")
    p.add_option('--credential',help="For creation of authfile or renewing the token within. If file not specified") 
    p.add_option('--authfile', help="Use to authenticate for automated operations.")
    p.add_option('--args', help="Use with --apx.")
    p.add_option('--value', help="Use with --customfield.")
    p.add_option('--targetgroup', help="Use with --usergroup and clone action.")
    p.add_option('--devices', help="Use with --servergroup or -g and \"info\" action. Prints server(s) in the servergroup")
    p.add_option('--showdevices', action="store_true",help="Use with --servergroup or -g and \"info\" action. Prints servergroup(s) in the given servergroup")
    p.add_option('--showservergroups', action="store_true",help="Use with --servergroup or -g and \"info\" action. Prints servergroup(s) in the given servergroup")
    options, arguments = p.parse_args()

    if options.username:
        password = getpass.getpass()
        s = SALib.SALib(username=options.username,password=password)
    elif options.authfile:
        try:
            authfd = open(options.authfile,'r')
            token = authfd.read()
            authfd.close()
        except IOError,args:
            print "authfile %s doesn't exists. exiting." % args.filename
            sys.exit(1)
        s = SALib.SALib(token=token)
    elif os.path.isfile("%s/.sacliToken" % homedir):
        try:
            authfd = open("%s/.sacliToken" % homedir,'r')
            token = authfd.read()
            authfd.close()
            s = SALib.SALib(token=token)
        except IOError,args:
            print "authfile %s doesn't exists. exiting." % args.filename
            sys.exit(1)
    else:
        s = SALib.SALib()

    # if len(sys.argv) > 2:
        # print "print options %s" % options
    if options.debug:
        s.setDebug(1)
    if options.credential:
        action = ['create']
        if arguments:
            if re.match('[Cc]reate',arguments[0]):
                try:
                    if options.debug:
                        print "options.credential: %s" % options.credential
                    credfd = open(str(options.credential),'w')
                    credfd.write(SALib.getToken())
                    credfd.close()
                except IOError,args:
                    print "Can't write credential file %s, check to make sure the directory exists and that you have permissions to write the file." % args.filename
                    sys.exit(1)
            else:
                print "Unknown Action: %s" % arguments[0]
                option_usage("With --credential=<%s> need to provide an action:" % object_list['credential'][2],action)
        else:
            option_usage("With --credential=<%s> need to provide an action:" % object_list['credential'][2],action)
    elif options.appconfig:
        action = ['list','namesearch','valuesearch','valuereplace','listvalueset']
        try:
            if arguments:
                if re.match('[Ll]ist',arguments[0]):
                    if options.regex:
                        useRegex = True
                    else:
                        useRegex = False
                    for i in s.getConfigurationRefs(options.appconfig,useRegex):
                        try:
                            print "%s|ConfigurationRef:%d" % (printObjectPath(s,[i]),i.id)
                        except SALib.AuthorizationDeniedException:
                            print "!!!%s is INACCESSIBLE!!!" % i
                            continue
                        except SALib.NotInFolder,i:
                            print "!!!%s is INACCESSIBLE!!!" % i
                            continue
                elif re.match('[Nn]amesearch',arguments[0]):
                    if options.name:
                        if options.regex:
                            dictConfigValueSet = s.findConfigurationName(options.appconfig,options.name,True)
                        else:
                            dictConfigValueSet = s.findConfigurationName(options.appconfig,options.name)
                        valueSetList = dictConfigValueSet.keys()
                        valueSetList.sort()
                        for i in valueSetList:
                            print "%s" % i
                            for j in dictConfigValueSet[i]:
                                print "%s: %s" % (j[0],j[1])
                            print
                    else:
                        print "Please provide --name=<name of default value> with namesearch action"
                elif re.match('[Vv]aluesearch',arguments[0]):
                    if options.value:
                        if options.regex:
                            dictConfigValueSet = s.findConfigurationValue(options.appconfig,options.value,True)
                        else:
                            dictConfigValueSet = s.findConfigurationValue(options.appconfig,options.value)
                        valueSetList = dictConfigValueSet.keys()
                        valueSetList.sort()
                        for i in valueSetList:
                            print "%s" % i
                            for j in dictConfigValueSet[i]:
                                print "%s: %s" % (j[0],j[1])
                            print
                    else:
                        print "Please provide --value=<name of default value> with valuesearch action"
                elif re.match('[Vv]aluereplace',arguments[0]):
                    if options.name and options.value:
                        if options.regex:
                            updateResult = s.replaceConfigurationValue(options.appconfig,options.name,options.value,True)
                        else:
                            updateResult = s.replaceConfigurationValue(options.appconfig,options.name,options.value)
                        configRefList = updateResult.keys()
                        configRefList.sort()
                        for configRef in configRefList:
                            if updateResult[configRef]:
                                print "%s: Modified" % configRef
                            else:
                                print "%s: Unchanged" % configRef
                    else:
                        print "Please provide both --name=<appconfig name> and --value=<replacement value> with valuereplace action"
                elif re.match('[Vv]aluesets?',arguments[0]):
                    dictConfigValueSet = s.listValueSet(options.appconfig)
                    valueSetList = dictConfigValueSet.keys()
                    valueSetList.sort()
                    for i in valueSetList:
                        print "%s" % i
                        for j in dictConfigValueSet[i]:
                            print "%s: %s" % (j[0],j[1])
                        print
                else:
                    print "Unknown Action: %s" % arguments[0]
                    option_usage("With --credential=<%s> need to provide an action:" % object_list['appconfig'][2],action)
            else:
                option_usage("With --appconfig=<%s> you need to provide an action:" % object_list['appconfig'][2],action)
        except Exception, e:
            raise
    elif options.server:
        # action = ['info','policy','list','run','attach','history']
        action = ['info','policystatus','list','history','update','showcustomfields']
        try:
            if arguments:
                # if arguments[0] == 'info':
                if re.match('[Ii]nfo',arguments[0]):
                    if options.dvcid:
                        for i in s.getServerRefs(options.server):
                            print "Server: %s ID: %d" % (i.name,i.id)
                    else:
                        for i in s.getServerRefs(options.server):
                            print "Server: %s" % i.name
                            print_serverinfo(s,'s.getServerInfo',i)
                            print
                # elif arguments[0] == 'policystatus':
                elif re.match('[Pp]olicystatus',arguments[0]):
                    sref = s.getServerRefs(options.server)
                    policyState = s.getPolicyAttachableStates(options.server)
                    policyStateKeys = policyState.keys()
                    policyStateKeys.sort()
                    print "Server: %s" % sref[0]
                    for i in policyStateKeys:
                        print "SoftwarePolicy: %s" % policyState[i]['SoftwarePolicy']
                        print "Remediated: %s" % policyState[i]['Remediated'] 
                        print "Attached: %s" % policyState[i]['Attached'] 
                        print
                elif re.match('[Ll]ist',arguments[0]):
                    if options.regex:
                        serverRefsList = s.getServerRefs(options.server,True)
                    else:
                        serverRefsList = s.getServerRefs(options.server)
                    for i in serverRefsList:
                        print "%s" % i
                elif arguments[0] == 'run':
                    if options.serverscript:
                        jobId = s.runServerScript(options.serverscript,options.server)
                        print "JobID: %s" % jobId
                    else:
                        print "Please provide --serverscript=<SA Server script> with run action"
                elif arguments[0] == 'attach':
                    if options.spolicy:
                        print "%s" % options.spolicy
                    else:
                        print "--spolicy=<spolicy id or path and name> needs to be used with attach."
                elif arguments[0] == 'history':
                    if options.days:
                        for i in s.getServerRefs(options.server):
                            print "Server Name: %s" % i.name
                            for j in s.getServerHistorybyDays(i,string.atol(options.days)):
                                print "%s" % re.sub('[{}]','',"%s" % j)
                        print "%s" % options.days
                    elif options.weeks:
                        print "%s" % options.weeks
                    else:
                        option_usage("With --server=<%s> [--days=<num of days> --weeks=<num of weeks]" % \
                                                                    object_list['server'][2],'')
                elif arguments[0] == 'update':
                    if options.customfield:
                        if not options.value:
                            print "No value option given will clear this Customfield value, previous value is: %s" % \
                                                    s.getCustomField(options.server,options.customfield)
                        s.updateCustomField(options.server,options.customfield,options.value)
                    else:
                        print "Must provide --customfield and --value option."
                elif re.match('showcustomfields?',arguments[0]):
                    if options.customfield:
                        value = s.getCustomField(options.server,options.customfield)
                        if not value:
                            value = ''
                        print "%s: %s" % (options.customfield,value)
                    else:
                        for i in s.listCustomFields(options.server):
                            print "%s" % i
                else:
                    print "Unknown Action: %s" % arguments[0]
                    option_usage("With --server=<%s> need to provide an action:" % object_list['server'][2],action)
            else:
                option_usage("With --server=<%s> you need to provide an action:" % object_list['server'][2],action)
        except SALib.NoServerRefFound,sref:
            print "ERROR: Couldn't find %s." % sref
        except SALib.MultipleServerRefsFound,sref:
            print "ERROR: Multiple Servers found: %s, specify only one server for this operation." % sref
        except SALib.NullSearchValue,sref:
            print "ERROR: Empty Search Value given."
        except SALib.MultipleObjectRefsFound,sref:
            print "ERROR: Multiple Servers found: %s, specify only one server for this operation." % sref
    elif options.spolicy:
        action = ['list','listitems','additems','replaceitems','deleteitems','create']
        if arguments:
            if re.match('[Ll]ist$',arguments[0]):
                objPaths = []
                if options.regex:
                    softwarePolicyRefs = s.getSoftwarePolicyRefs(options.spolicy,True)
                else:
                    softwarePolicyRefs = s.getSoftwarePolicyRefs(options.spolicy)
                for i in softwarePolicyRefs:
                    try:
                        print "%s|SoftwarePolicyRefs:%d" % (printObjectPath(s,[i]),i.id)
                        # pathDict = s.getObjectPath([ i ],False)   
                        # (parentPath,SP) = os.path.split(pathDict[i])
                        # if parentPath == "/":
                    #       print "%s%s" % (parentPath,i)
                    #   else:
                    #       print "%s/%s" % (parentPath,i)
                    except SALib.AuthorizationDeniedException:
                        print "!!!%s is INACCESSIBLE!!!" % i
                        continue
                    except SALib.NotInFolder,i:
                        print "!!!%s is INACCESSIBLE!!!" % i
                        continue
            elif re.match('[Aa]dditems?',arguments[0]):
                try:
                    if options.policyitem:
                        policyItemRefs = createPolicyItemList(s,options.policyitem)
                        print "%s" % policyItemRefs
                        if options.order:
                            print "%s has been updated." % s.addSoftwarePolicyItem(options.spolicy,policyItemRefs,options.order).ref
                        else:
                            print "%s has been updated." % s.addSoftwarePolicyItem(options.spolicy,policyItemRefs).ref
                    else:
                        print "With --spolicy and action additems you need to provide --policyitem"
                except SALib.UnknownPolicyItemType,args:
                    print "Incorrect policy item specified with --policyitem. (i.e. use a format like RPMRef:100006)"
                except SALib.DuplicatePolicyItemFound,args:
                    print "The policyitem %s already exist in the software policy." % args
            elif re.match('[Rr]eplaceitems?',arguments[0]):
                if options.policyitem:
                    if options.order:
                        try:
                            policyItemRef = createPolicyItemList(s,options.policyitem)
                            print "%s" % policyItemRef
                            if len(policyItemRef) > 1:
                                print "You need to provide only one --policyitem because you can only replace items one at a time." 
                                sys.exit()
                            sref = s.replaceSoftwarePolicyItembyPosition(options.spolicy,policyItemRef[0],options.order).ref
                            print "%s has been updated" % sref
                        except SALib.NoObjectRefFound,args:
                            print "Couldn't find policy item %s to replace" % args
                        except SALib.NotSoftwarePolicyItem,args:
                            print "The referenced item %s can't be added to a software policy." % args
                        except IndexError,args:
                            print "%s is an incorrect SA Object type. Check the issued --policyitem args for the correct type." % \
                                        options.policyitem  
            elif re.match('[Dd]eleteitems?',arguments[0]):
                if options.order:
                    print "%s has been updated" % s.deleteSoftwarePolicyItembyPosition(options.spolicy,options.order).ref
            elif re.match('[Ll]istitems?',arguments[0]):
                for spolicyRef in s.getSoftwarePolicyRefs(options.spolicy):
                    try:
                        print "software policy:"
                        print "%s|SoftwarePolicyRef:%s" % (printObjectPath(s,[spolicyRef]),spolicyRef.id)
                        print "items:"
                        listSPItems = s.listSoftwarePolicyItems(spolicyRef.id)
                        seqNumber = 1
                        for item in listSPItems[spolicyRef]:
                            itemRef = re.sub('(.*)(\()([A-Za-z]*\:[0-9]*[^)])(\).*)','\\3',"%s" % item)
                            policyItem = "%s|%s" % (itemRef,printObjectPath(s,[item]))
                            print "%d|%s" % (seqNumber,policyItem)
                            seqNumber += 1
                        print
                    except SALib.AuthorizationDeniedException:
                        print "!!!%s is INACCESSIBLE!!!" % i
                        continue
                    except SALib.NotInFolder,i:
                        print "!!!%s is INACCESSIBLE!!!" % i
                        continue
            elif re.match('[Cc]reate',arguments[0]):
                pass
            else:
                option_usage("With --spolicy=<%s> you need to provide an action:" % object_list['spolicy'][2],action)
        else:
            option_usage("With --spolicy=<%s> you need to provide an action:" % object_list['spolicy'][2],action)
    elif options.platform and not options.package:
        action = ['list']
        if arguments:
            if re.match('[Ll]ist',arguments[0]):
                if options.regex:
                    platformRefsList = s.getPlatformRefs(options.platform,True)
                else:
                    platformRefsList = s.getPlatformRefs(options.platform)
                for i in platformRefsList:
                    print "%s" % i
            else:
                option_usage("With --platform=<%s> you need to provide an action:" % object_list['platform'][2],action)
        else:
            option_usage("With --platform=<%s> you need to provide an action:" % object_list['platform'][2],action)
    elif options.folder and not (options.pkgtype):
        action = ['info','listfolder','list','listregex','listall','remove','create','addACL','removeACL','listACL']
        try:
            if arguments:
                if re.match('[Ll]ist',arguments[0]):
                    if re.match('[Ll]istregex',arguments[0]):
                        folderRefs = s.getFolderRefs(options.folder,True)
                    elif re.match('[Ll]istall',arguments[0]):
                        folderRefs = s.getFolderRefs(options.folder,False,True)
                    else:
                        folderRefs = s.getFolderRefs(options.folder,False)
                    for i in folderRefs:
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
                elif re.match('[Ii]nfo',arguments[0]):
                    print "Folder: %s" % options.folder 
                    print_folderinfo(s,'s.getFolderInfo',options.folder)
                    print
                elif arguments[0] == 'create':
                    print "Folder: %s" % options.folder 
                    s.createFolder(options.folder)
                elif arguments[0] == "remove":
                    print "Folder: %s" % options.folder 
                    recursive = False
                    if options.recursive:
                        recursive = True
                    s.removeFolder(options.folder,recursive)
                elif re.match('[Ll]istfolders?',arguments[0]):
                    recursive = False
                    if options.recursive: 
                        recursive = True
                    s.listFolder(options.folder,recursive,'')
                elif arguments[0] == "addACL":
                    recursive = False
                    applytoparent = False
                    if options.perm and options.usergroup:
                        if options.applytoparent:
                            applytoparent = True
                        if options.recursive:
                            recursive = True
                        addedACL = s.addFolderACLs(options.folder,options.perm,options.usergroup,recursive,applytoparent)
                        for i in addedACL:
                            print "%s" % i
                    else:
                        print "With addACL action you must provide: --folder=<folder name> --perm=<permissions> --usergroup=<usergroup name>"
                        print "perm can be comma delimited string: l,r,w,x"
                        print "where l is list,r is read, w is write, and x is execute"
                        print 'i.e. --perm=l,r,w'
                elif arguments[0] == "listACL":
                    s.listFolderACLs(options.folder)
                elif arguments[0] == "removeACL":
                    recursive = False
                    applytoparent = False
                    if options.usergroup:
                        if options.applytoparent:
                            applytoparent = True
                        if options.recursive:
                            recursive = True
                        if options.perm:
                            perm = options.perm
                        else:
                            perm = "l,r,w,x,p"
                            print "Removing all permissions from folder %s for usergroup %s" % (options.folder,options.usergroup)
                        removedACL = s.removeFolderACLs(options.folder,perm,options.usergroup,recursive)
                        for i in removedACL:
                            print "%s" % i
                    else:
                        print "With removeACL action you must provide: --folder=<folder name> --usergroup=<usergroup name>"
                        print "Optionally provide --perm, if not provided then all permissions for usergroup will be removed from the folder"
                        print "perm can be comma delimited string: l,r,w,x"
                        print "where l is list,r is read, w is write, and x is execute"
                        print "i.e. --perm='l,r,w'"
                else:
                    option_usage("With --folder=<%s> you need to provide an action:" % object_list['folder'][2],action)
            else:
                option_usage("With --folder=<%s> you need to provide an action:" % object_list['folder'][2],action)
        except SALib.MultipleFolderRefsFound,args:
            print "ERROR: Multiple folders found: %s." % args
        except SALib.NullSearchValue,args:
            print "ERROR: Empty Search Value given."
        except SALib.RegExInvalid,args:
            print "ERROR: RegEx is invalid. the following message was given by python module sre_constants: %s" % args
    elif options.servergroup:
        action = ['info','listall','listgroup','remove','create','list','listregex','addservers','removeservers','listdevice']
        try:
            if arguments:
                if arguments[0] == 'info':
                    print "Server Group Name: %s" % (options.servergroup,)
                    print_servergroupinfo(s,'s.getServerGroupInfo',options.servergroup)
                elif re.match('[Ll]istdevices?',arguments[0]):
                    for i in s.getServerGroupInfo(options.servergroup)['devices']:
                        print "%s" % i
                elif re.match('[Ll]istgroups?',arguments[0]):
                    for i in s.getServerGroupInfo(options.servergroup)['children']:
                        print "%s" % i
                elif arguments[0] == 'create':
                    if options.devices:
                        if options.expression:
                            print "You can't add device(s) to a dynamic group. Using the expression option implies that this is a dynamic group."
                        else:
                            s.createServerGroup(options.servergroup,options.devices)
                    elif options.expression:
                        s.createServerGroup(options.servergroup,isDynamic=True,ruleExpression=options.expression)
                    elif options.empty:
                        s.createServerGroup(options.servergroup,dvc_list=[])
                    else:
                        print "ERROR: Need to specify --devices,--expression,or --empty to create either a static group, a dynamic group, or an empty server group respectively." 
                elif re.match('[Rr]emove',arguments[0]):
                    s.removeServerGroup(options.servergroup)
                elif re.match('[Aa]ddservers?',arguments[0]):
                    if options.devices:
                        s.addServersToServerGroup(options.devices,options.servergroup)
                    else:
                        print "ERROR: Need to specify the devices to add with --devices=<server names,>"
                        sys.exit(1)
                elif re.match('[Rr]emoveservers?',arguments[0]):
                    if options.devices:
                        s.removeServersFromServerGroup(options.devices,options.servergroup)
                    else:
                        print "ERROR: Need to specify the devices to remove with --devices=<server names,>"
                        sys.exit(1)
                elif re.match('[Ll]ist',arguments[0]):
                    if re.match('[Ll]istall',arguments[0]):
                        for i in list(s.getServerGroupInfo(options.servergroup)['children']): print "%s" % i
                        for i in list(s.getServerGroupInfo(options.servergroup)['devices']): print "%s" % i
                    # elif re.match('[Ll]istregex',arguments[0]):
                    else:
                        for i in s.getDeviceGroupRefs(options.servergroup):
                            dvcGroupVO = s.callUAPI('device.DeviceGroupService','getDeviceGroupVO',i)
                            print "%s (DeviceGroupRef: %d)" % (re.sub('^Device Groups','',dvcGroupVO.fullName),i.id)
                elif re.match('[Rr]egexlist',arguments[0]):
                    for i in s.getDeviceGroupRefs(options.servergroup,True):
                        dvcGroupVO = s.callUAPI('device.DeviceGroupService','getDeviceGroupVO',i)
                        print "%s (DeviceGroupRef: %d)" % (re.sub('^Device Groups','',dvcGroupVO.fullName),i.id)
                else:
                    option_usage("With --servergroup=<%s> you need to provide an action:" % \
                                                                        object_list['servergroup'][2],action)
            else:
                option_usage("With --servergroup=<%s> you need to provide an action:" % \
                                                                    object_list['servergroup'][2],action)
        except SALib.NoDeviceGroupRefFound,sgref:
            print "ERROR: Could not find Server Group %s" % options.servergroup
        except SALib.MultipleDeviceGroupRefsFound,sgref:
            print "ERROR: Multiple Server Groups matched %s. Specify a specific one." % sgref 
        except SALib.ObjectAlreadyExists:
            print "ERROR: Server Group %s already exists." % options.servergroup
    elif options.usergroup:
        action = ['list','clone','userlist','grouplist','sync_ogfs','sync_features','sync_resources']
        try:
            if arguments:
                if arguments[0] == "list":
                    for i in s.getUserRoleRefs(options.usergroup):
                        print "%s" % i
                elif arguments[0] == 'grouplist':
                    for i in s.getUserGroupfromUser(options.usergroup):
                        print "%s" % i
                elif arguments[0] == 'userlist':
                    for i in s.getUserListfromUserGroup(options.usergroup):
                        print "%s" % i
                elif arguments[0] == 'clone':
                    if options.targetgroup:
                        s.cloneUserGroup(options.usergroup,options.targetgroup)
                    else:
                        print "You must specify --targetgroup=<group name> with action clone,sync_ogfs,sync_features,sync_resources."
                elif arguments[0] == 'sync_ogfs':
                    if options.targetgroup:
                        s.globalShellPermissionsSync(options.usergroup,options.targetgroup)
                    else:
                        print "You must specify --targetgroup=<group name> with action clone,sync_ogfs,sync_features,sync_resources."
                elif arguments[0] == 'sync_features':
                    if options.targetgroup:
                        s.featurePermissionsSync(options.usergroup,options.targetgroup)
                    else:
                        print "You must specify --targetgroup=<group name> with action clone,sync_ogfs,sync_features,sync_resources."
                elif arguments[0] == 'sync_resources':
                    if options.targetgroup:
                        s.resourcePermissionsSync(options.usergroup,options.targetgroup)
                    else:
                        print "You must specify --targetgroup=<group name> with action clone,sync_ogfs,sync_features,sync_resources."
                else:
                    print "With --usergroup=<%s> Provide an action: %s" % \
                                            (object_list['usergroup'][2],action)
            else:
                p.print_help()
        except SALib.ObjectAlreadyExists,args:
            print "ERROR: User Group %s already exists." % args
        except SALib.MultipleUserGroupFound,args:
            print "ERROR: Multiple User Groups matched %s. Specify a specific one." % args 
        except SALib.NoObjectRefFound,args:
            print "ERROR: Could not find User Group %s." % args
        except SALib.PytwistCallException,args:
            print "An Exception making this call resulted in the message: %s" % args
    elif options.customfield:
        action = ['create','delete']
        if arguments:
            if arguments[0] == 'create':
                s.createCustomField(options.customfield)
            elif arguments[0] == 'delete':
                s.deleteCustomField(options.customfield)
            else:
                print "Need an action"
                print "With --customfield=<%s> need to provide an action: %s" % \
                                                        (object_list['apx'][2],action)
        else:
            print "With --customfield you must provide an action: %s" % action
    elif options.apx:
        action = ['run','list']
        if arguments:
            if re.match('[Rr]un',arguments[0]):
                if options.args:
                    args = options.args
                else:
                    args = ''   
                jobid = s.startProgramAPX(options.apx,args)
                print "%s" % jobid
            elif re.match('[Ll]ist',arguments[0]):
                for i in s.getAPXRefs(options.apx):
                    print "%s" % i
            else:
                option_usage("With --apx=<%s> you need to provide an action:" % \
                                                                            object_list['apx'][2],action)
        else:
            option_usage("With --apx=<%s> you need to provide an action:" % \
                                                                        object_list['apx'][2],action)
    elif options.searchobj:
        action = ['search','getattribute','getoperator']
        try:
            if arguments:
                if re.match('getattributes?',arguments[0]):
                    for i in s.getSearchableAttributes(options.searchobj):
                        print "%s" % i
                elif re.match('getoperators?',arguments[0]):
                    if options.attribute:
                        for i in s.getSearchableAttributeOperators(options.searchobj,options.attribute):
                            print "%s" % i
                    else:
                        print "You must provide --attribute with getoperator action"
                elif arguments[0] == 'search':
                    if options.expression:
                        for i in s.findObjRefs(options.searchobj,options.expression):
                            print "%s" % i
                    else:
                        print "You must provide --expression with search action"
                else:
                    option_usage("With --searchobj=<%s> you need to provide an action:" % \
                                                                        object_list['searchobj'][2],action)
            else:
                option_usage("With --searchobj=<%s> you need to provide an action:" % \
                                                                    object_list['searchobj'][2],action)
        except SALib.UnknownSearchType,args:
            print "Search type %s doesn't exist. Use --listsearchtypes to see a list of valid search types." % args
        except SALib.UnknownSearchAttribute,args:
            print "Search attributes %s doesn't exist. Use --searchobj=<searchobj> getattribute" % args
        except SALib.InvalidSearchExpression,args:
            print "The grammer for the given expression %s produced this message -> %s. Use --filtersyntax to get a printed reference." % (options.expression,args)
    elif options.filtersyntax:
        print "'{ <searchAttribute> <searchOperator> \"<searchValue>\" }'"
        print "'{ <searchAttribute> <searchOperator> \"<searchValue>\" } [&|] { expression }'"
        print "'{ <searchAttribute> <searchOperator> \"<searchValue>\" } [&|] { { expression } [&|] { expression } }'"
        print "If you use a mix of & and | make sure to subgroup i.e. { expression } & { { expression } | { expression } }"
        print "You can use either {} or (). Refer to SA Developer's Guide in the Appendix for more details on filter expression."
    elif options.listsearchtypes:
        for i in s.getSearchableTypes():
            print "%s" % i
    elif options.listpkgtypes:
        for i in s.getUnitTypes():
            print "%s" % i.typeName
    elif options.serverscript and not (options.server or options.servergroup):
        action = ['info','list']
        if arguments:
            if re.match('[Ii]nfo',arguments[0]):
                for i in s.getServerScriptRefs(options.serverscript):
                    print "Server Script: %s" % i.name
                    print_serverscriptinfo(s,'s.getServerScriptInfo',i)
                    folderdict = s.getServerScriptInfo(i)
                    print "location: %s" % s.getObjectPath( [ folderdict['folder'] ])
                    print "source: \n%s" % s.showServerScriptSource(i)
            elif re.match('[Ll]ist',arguments[0]):
                if re.match('[Ll]istregex',arguments[0]):
                    serverScriptRefs = s.getServerScriptRefs(options.serverscript,True)
                else:
                    serverScriptRefs = s.getServerScriptRefs(options.serverscript,False)
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
            else:
                option_usage("With --serverscript=<%s> you need to provide an action:" % \
                                                                    object_list['serverscript'][2],action)
        else:
            option_usage("With --serverscript=<%s> you need to provide an action:" % \
                                                            object_list['serverscript'][2],action)
    elif options.job:
        action = ['results']
        try:
            if arguments:
                if re.match('[Rr]esults?',arguments[0]):
                    jobResultDict = s.getJobResults(options.job)['hosts']
                    hostKeys = jobResultDict.keys()
                    hostKeys.sort()
                    for host in hostKeys:
                        print '-------------------------------------------------------------------------------'
                        print "%s" % host
                        jobResults = jobResultDict[host].keys()
                        jobResults.sort()
                        for i in jobResults:
                            if re.match('(stderr|stdout|tailStderr|tailStdout)',i):
                                print "%s:\n%s" % (i,jobResultDict[host][i])
                            else:
                                print "%s: %s" % (i,jobResultDict[host][i])
                        print '-------------------------------------------------------------------------------'
                        print
                else:
                    option_usage("With --job=<%s> you need to provide an action:" % \
                                                                object_list['job'][2],action)
            else:
                option_usage("With --job=<%s> you need to provide an action:" % \
                                                                    object_list['job'][2],action)
        except SALib.JobTypeNotImplemented,args:
            print "sacli can't report on the job type %s yet." % args
        except SALib.SAAttributeNotFound:
            print "Please specify a job id which is either an integer or long." % options.job
        except IndexError,args:
            print "Either the job doesn't exist, or you don't have permissions to access the job."
    elif options.package:
        action = ['list','download','upload']
        try:
            if arguments:
                if re.match('[Ll]ist',arguments[0]):
                    if options.regex:
                        unitRefsList = s.getUnitRefs(options.package,True)
                    else:
                        unitRefsList = s.getUnitRefs(options.package)
                    for i in unitRefsList:
                        try:
                            pathDict = s.getObjectPath([ i ],False) 
                            (parentPath,SP) = os.path.split(pathDict[i])
                            if parentPath == "/":
                                print "%s%s" % (parentPath,i)
                            else:
                                print "%s/%s" % (parentPath,i)
                        except SALib.NotInFolder,args:
                            print "Package %s is not accessible in HP SA folders. Check old package repository structure. (i.e. pre HP SA 7.x) " % args
                            continue
                elif re.match('[Uu]pload',arguments[0]):
                    if options.platform and options.pkgtype and options.folder:
                        if options.regex:
                            unitId = s.uploadUnit(options.package,options.pkgtype,options.platform,options.folder,options.regex)
                        else:
                            unitId = s.uploadUnit(options.package,options.pkgtype,options.platform,options.folder)
                        print "Created Unit ID: %s" % unitId
                    else:
                        if not options.platform:
                            option_usage("With --package=<%s> you need to provide --platform with action %s" % \
                                                                            object_list['package'][2],action)
                        if not options.pkgtype:
                            option_usage("With --package=<%s> you need to provide --pkgtype with action %s" % \
                                                                            object_list['package'][2],action)
                        if not options.folder:
                            option_usage("With --package=<%s> you need to provide --folder with action %s" % \
                                                                            object_list['package'][2],action)
                elif re.match('[Dd]ownload',arguments[0]):
                    if options.outfile:
                        if options.regex:
                            s.downloadUnit(options.package,option.outfile,options.regex)
                        else:
                            s.downloadUnit(options.package,option.outfile)
                    else:
                        option_usage("With --package=<%s> you need to provide --outfile with action %s" % \
                                                                            object_list['package'][2],action)
                else:
                    option_usage("With --package=<%s> you need to provide an action:" % \
                                                                    object_list['package'][2],action)
            else:
                option_usage("With --package=<%s> you need to provide an action:" % \
                                                        object_list['package'][2],action)
        except SALib.SoftwareRepositoryUploadFailed,args:
            if re.search('invalid token',"%s" % args):
                print "Upload of package failed due to invalid credentials. The message from the twist is: %s" % args
            elif re.search('incompatible with unit_type',"%s" % args):
                print "Upload of package failed due to platform and unit type mismatch. The message from the twist is: %s" % args
            else:
                print "Upload of package failed with the following message: %s" % args
        except SALib.SoftwareRepositoryDownloadFailed,args:
            if re.search('invalid token',"%s" % args):
                print "Download of package failed due to invalid credentials. The message from the twist is: %s" % args
            elif re.search('incompatible with unit_type',"%s" % args):
                print "Download of package failed due to platform and unit type mismatch. The message from the twist is: %s" % args
        except SALib.NoObjectRefFound,args:
            print "ObjectRef was not found: %s" % args
    else:
        p.print_help()
    
if __name__ == '__main__':
    try:
        main()
    except (SALib.AuthenticationFailed):
        print "sacli is exiting because it couldn't authenticate the user."
    except (SystemExit):
        print "sacli is exiting due to invalid options or incorrect input."
    except (KeyboardInterrupt):
        print "sacli is exiting because it received a Ctrl-C sequence from the keyboard."
    except OSError,args:
        print "OS had problems performing system call: %s" % args
    except SALib.RegExInvalid,args:
        print "Regular Expression is invalid the message was: %s" % args
