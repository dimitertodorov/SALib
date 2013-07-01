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

#
# Adding a dictionary to be able to list different objects within a folder
#
folderSAObjType = {
    'APXRef' : 'com.opsware.apx.APXRef',
    'AuditPolicyRef' : 'com.opsware.compliance.sco.AuditPolicyRef',
    'CMLRef' : 'com.opsware.acm.CMLRef',
    'ConfigurationRef' : 'com.opsware.acm.ConfigurationRef',
    'FolderRef' : 'com.opsware.folder.FolderRef',
    'MSIRef' : 'com.opsware.pkg.windows.MSIRef',    
    'OSBuildPlanRef' : 'com.opsware.osprov.OSBuildPlanRef',
    'OSSequenceRef' : 'com.opsware.osprov.OSSequenceRef',
    'ProgramAPXRef' : 'com.opsware.apx.ProgramAPXRef',
    'RPMRef' : 'com.opsware.pkg.RPMRef',
    'SoftwareRef' : 'com.opsware.pkg.SoftwareRef',
    'SoftwarePolicyRef' : 'com.opsware.swmgmt.SoftwarePolicyRef',
    'SolPkgRef' : 'com.opsware.pkg.solaris.SolPkgRef',
    'SolPatchClusterRef' : 'com.opsware.pkg.solaris.SolPatchClusterRef',
    'ServerScriptRef' : 'com.opsware.script.ServerScriptRef',    
    'WebAPXRef' : 'com.opsware.apx.WebAPXRef',
    'ZIPRef' : 'com.opsware.pkg.ZIPRef'
}

def main():
    p = sacliutil.standardOptions("folder --id=<identifier> [--<modifier options>] [ <action> ]")
    p.add_option('--id', help="folder path or id")
    p.add_option('--recursive', action="store_true",help="Recursively traverse the folders.")
    p.add_option('--type', help="Filter by SA Object type.")
    (options,arguments) = p.parse_args()
    s = sacliutil.getSALib(options.username,options.password,options.authfile)

    if options.debug:
        s.setDebug(1)
    if options.id:
        action = ['info','listsaobj','list','listall','remove','create','addacl','removeacl','listacl']
        try:
            if arguments:
                if re.match('[Ll]ist$',arguments[0]):
                    if options.regex:
                        folderRefs = s.getFolderRefs(options.id,True)
                    else:
                        folderRefs = s.getFolderRefs(options.id,False)
                    for i in folderRefs:
                        try:
                            if i.id == 0:
                                print "/|%s" % sacliutil.printObjectID(i)
                            else:
                                print "%s|%s" % (sacliutil.printObjectPath(s,[i]),sacliutil.printObjectID(i))
                        except SALib.AuthorizationDeniedException:
                            print "!!!%s is INACCESSIBLE!!!" % i
                            continue
                        except SALib.NotInFolderException:
                            print "!!!%s is INACCESSIBLE!!!" % i
                elif re.match('[Ll]istall',arguments[0]):
                    if options.regex:
                        folderRefs = s.getFolderRefs(options.id,True,True)
                    else:
                        folderRefs = s.getFolderRefs(options.id,False,True)
                    for i in folderRefs:
                        try:
                            print "%s|%s" % (sacliutil.printObjectPath(s,[i]),sacliutil.printObjectID(i))
                            #pathDict = s.getObjectPath([ i ],False)
                            #(parentPath,SP) = os.path.split(pathDict[i])
                            #if parentPath == "/":
                            #    print "%s%s" % (parentPath,i)
                            #else:
                            #    print "%s/%s" % (parentPath,i)
                        except SALib.AuthorizationDeniedException:
                            print "!!!%s is INACCESSIBLE!!!" % i
                            continue
                        except SALib.NotInFolderException:
                            print "!!!%s is INACCESSIBLE!!!" % i
                elif re.match('[Ii]nfo',arguments[0]):
                    print "Folder: %s" % options.id
                    sacliutil.print_folderinfo(s,'s.getFolderInfo',options.id)
                    print
                elif arguments[0] == 'create':
                    print "Folder: %s" % options.id
                    s.createFolder(options.id)
                elif arguments[0] == "remove":
                    print "Folder: %s" % options.id
                    recursive = False
                    if options.recursive:
                        recursive = True
                    s.removeFolder(options.id,recursive)
                elif re.match('[Ll]istsaobj?',arguments[0]):
                    recursive = False
                    if options.recursive:
                        recursive = True
                    if options.type in folderSAObjType.keys():
                        s.printFolderObj(options.id,recursive,options.type)
                    elif not options.type:
                        s.printFolderObj(options.id,recursive,'')
                    else:
                        print "They type you've referenced in --type does not exist or is not yet implemented."
                        print "The list of valid types are: %s" % folderSAObjType.keys()
                elif arguments[0] == "addacl":
                    recursive = False
                    applytoparent = False
                    if options.perm and options.usergroup:
                        if options.applytoparent:
                            applytoparent = True
                        if options.recursive:
                            recursive = True
                        addedACL = s.addFolderACLs(options.id,options.perm,options.usergroup,recursive,applytoparent)
                        for i in addedACL:
                            print "%s" % i
                    else:
                        print "With addacl action you must provide --perm=<permissions> and --usergroup=<usergroup name>"
                        print "perm can be comma delimited string: l,r,w,x"
                        print "where l is list,r is read, w is write, and x is execute"
                        print 'i.e. --perm=l,r,w'
                elif arguments[0] == "listacl":
                    s.listFolderACLs(options.id)
                elif arguments[0] == "removeacl":
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
                            print "Removing all permissions from folder %s for usergroup %s" % (options.id,options.usergroup)
                        removedACL = s.removeFolderACLs(options.id,perm,options.usergroup,recursive)
                        for i in removedACL:
                            print "%s" % i
                    else:
                        p.print_help()
                        print "With removeacl action you must provide --usergroup=<usergroup name>"
                        print "Optionally provide --perm, if not provided then all permissions for usergroup will be removed from the folder"
                        print "perm can be comma delimited string: l,r,w,x"
                        print "where l is list,r is read, w is write, and x is execute"
                        print "i.e. --perm='l,r,w'"
                else:
                    p.print_help()
                    print "Please provide an action: %s" % sacliutil.getActionList(action)
            else:
                p.print_help()
                print "Please provide an action: %s" % sacliutil.getActionList(action)
        except SALib.MultipleFolderRefsFound,args:
            print "ERROR: Multiple folders found: %s." % args
        except SALib.NullSearchValue,args:
            print "ERROR: Empty Search Value given."
        except SALib.RegExInvalid,args:
            print "ERROR: RegEx is invalid. the following message was given by python module sre_constants: %s" % args
    else:
        p.print_help()



if __name__ == '__main__':
    try:
        main()
    except (SALib.AuthenticationFailed):
        print "folder cmd is exiting because it couldn't authenticate the user."
    except (KeyboardInterrupt):
        print "folder cmd is exiting because it received a Ctrl-C sequence from the keyboard."
    except OSError,args:
        print "OS had problems performing system call: %s" % args
    except SALib.RegExInvalid,args:
        print "Regular Expression is invalid the message was: %s" % args
