import os
import re
import string
import sys
import time
import optparse
import SALib
import getpass
import subprocess

defaultTokenDir = '.sacli'
defaultTokenFile = 'default'
filecmd = '/usr/bin/file'
filecmdoptions = ' --mime -b '
version = "2.2.20"

def _print_dict(s,method_call,dict_obj):
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

def print_unitinfo(s,salib_call,unit):
    _print_dict(s,salib_call,unit)

def print_cmlinfo(s,salib_call,cml):
    _print_dict(s,salib_call,cml)

def printObjectID(saobjectref):
    return re.sub('(.*\()([A-Za-z]+\:[0-9]*[^)])(\\).*)','\\2',"%s" % saobjectref)

def printObjectPath(s,ObjectRef):
    if len(ObjectRef) > 1:
        SALib.MultipleObjectRefsFound,ObjectRef
    pathDict = s.getObjectPath(ObjectRef,False)
    return "%s" % pathDict[ObjectRef[0]]

def getActionList(action):
    actionString = ""
    for i in action:
       actionString += "%s, " % i 
    return actionString.strip(", ")

def createPolicyItemList(s,policyItemString):
    policyItemRefs = []
    itemList = re.split('[,]',policyItemString)
    for item in itemList:
        if not item:
            break
        if re.search('[/]',item):
            policyItemRefs += s.getFolderRefs(item,regex=False,listall=True)
        elif re.search('[:]',item):
            (ref,id) = re.split('[:]',re.sub('(.*\()([A-Za-z]+\:[0-9]*[^)])(\\).*)','\\2',item))
            try:
                refInstance = eval("SALib.%s(%s)" % (ref,id))
            except AttributeError, args:
                raise SALib.UnknownPolicyItemType,item
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

def getSAObjectRefsOrString(s,saObjectRefsString):
    if not re.search('[A-Za-z]+Ref:[0-9]+',saObjectRefsString):
        return saObjectRefsString
    if re.search(',',saObjectRefsString):
        return createPolicyItemList(s,saObjectRefsString)
    else:
        return createPolicyItemList(s,saObjectRefsString)[0]
                
def standardOptions(usage):
    p = optparse.OptionParser(  usage=usage,\
                                version=version,\
                                description="Command line interface into HPSA (sacli %s)" % version,\
                                conflict_handler="resolve"  )
    p.add_option('--debug', action="store_true",help="Prints out debug info.")
    p.add_option('--regex', default=False, action="store_true",help="Interpret object string as a regular expression.")
    p.add_option('--username', help="Use to authenticate to HPSA (Opsware).")
    p.add_option('--password', help="Use to authenticate to HPSA (Opsware).")
    p.add_option('--authfile', help="Use to authenticate for automated operations.")
    return p

def getHomeDir():
    if 'HOMEDIR' in os.environ.keys():
        homedir = os.environ['HOMEDIR']
    elif 'HOME' in os.environ.keys():
        homedir = os.environ['HOME']
    else:
        homedir = '.'
    return homedir

def detectPkgType(filename,filecmd=filecmd,filecmdoptions=filecmdoptions):
    if os.path.exists(filecmd):
        pout = subprocess.Popen("%s %s '%s'" % (filecmd,filecmdoptions,filename),shell=True,stdout=subprocess.PIPE)
        filetype = re.split(';',pout.stdout.readlines()[0])[0]
        # uses mime typing to detect file type and returns SA package Types.
        if re.search('x-zip',filetype):
            filetype = 'ZIP'
        elif re.search('x-rpm',filetype):
            filetype = 'RPM'
        elif re.search('msword',filetype):
            filetype = 'MSI'
        elif re.search('octet-stream',filetype):
            filetype = 'EXE'
        else:
            filetype = None
        return filetype
    else:
        raise IOError,filecmd

def getSALib(username=None,password=None,authfile=None):
    if username and not authfile:
        if not password:
            if os.path.isfile("%s/%s/%s" % (getHomeDir(),defaultTokenDir,username)):
                tkfd = file("%s/%s/%s" % (getHomeDir(),defaultTokenDir,username),'r')
                token = tkfd.read()
                s = SALib.SALib(token=token)
            else:
                password = getpass.getpass()
                s = SALib.SALib(username=username,password=password)
        else:
            s = SALib.SALib(username=username,password=password)
    elif authfile:
        try:
            authfd = open(authfile,'r')
            token = authfd.read()
            authfd.close()
        except IOError,args:
            print "authfile %s doesn't exists. exiting." % args.filename
            sys.exit(1)
        s = SALib.SALib(token=token)
    elif os.path.isfile("%s/%s/%s" % (getHomeDir(),defaultTokenDir,defaultTokenFile)):
        try:
            authfd = open("%s/%s/%s" % (getHomeDir(),defaultTokenDir,defaultTokenFile),'r')
            token = authfd.read()
            authfd.close()
            s = SALib.SALib(token=token)
        except IOError,args:
            print "authfile %s doesn't exists. exiting." % args.filename
            sys.exit(1)
    else:
        try:
            s = SALib.SALib()
        except SALib.AuthenticationFailed:
            print "Unable to authenticate the user. Most likely a username wasn't given. Try using --username <username>"
            raise SALib.AuthenticationFailed
    return s

