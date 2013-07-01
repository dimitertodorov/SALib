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
import glob
import subprocess

#
# File command path and options -
# For the detection of file types.
#
filecmd = '/usr/bin/file'
cmdoptions = ' --mime -b '

def main():
    p = sacliutil.standardOptions("package --id=<identifier> [--<modifier options>] [ <action> ]")
    p.add_option('--id', help="Specify a identifier which is an Opsware ID, software policy name, or folder path and software policy name.")
    p.add_option('--platform', help="Use with upload action.")
    p.add_option('--pkgtype', help="Use with upload action.")
    p.add_option('--folder', help="Use with package upload.")
    p.add_option('--platform', help="Use with package upload.")
    p.add_option('--pkgfile', help="Use with upload or download action.")
    p.add_option('--pkgreplace', help="Use with overwrite action.")
    p.add_option('--pkgtypes', action="store_true", help="List package types.")
    p.add_option('--name', help="name to specify when calling update package attribute.")
    p.add_option('--value', help="value to specify when calling update package attribute.")
    (options,arguments) = p.parse_args()
    s = sacliutil.getSALib(options.username,options.password,options.authfile)

    if options.debug:
        s.setDebug(1)
    try:
        if options.id:
            action = ['list','download','update','info','overwrite','addplatform','updateplatform']
            if arguments:
                if re.match('[Ll]ist',arguments[0]):
                    if options.regex:
                        unitRefsList = s.getUnitRefs(options.id,True)
                    else:
                        unitRefsList = s.getUnitRefs(options.id)
                    for i in unitRefsList:
                        try:
                            print "%s|%s" % (sacliutil.printObjectPath(s,[i]),sacliutil.printObjectID(i))
                        except SALib.NotInFolder,args:
                            print "Package %s is not accessible in HP SA folders. Check old package repository structure. (i.e. pre HP SA 7.x) " % args
                            continue
                elif re.match('[Ii]nfo',arguments[0]):
                    for i in s.getUnitRefs(options.id):
                        print "SA Unit ---- %s ----" % i.name
                        sacliutil.print_unitinfo(s,'s.getUnitInfo',i)
                        print
                elif re.match('[Dd]ownload',arguments[0]):
                    if options.regex:
                        s.downloadUnit(options.id,options.pkgfile,options.regex)
                    else:
                        s.downloadUnit(options.id,options.pkgfile)
                elif re.match('(?i)^update$',arguments[0]):
                    if options.name and options.value:
                        value = sacliutil.getSAObjectRefsOrString(s,options.value)
                        unitId = s.updateUnitVO(options.id,options.name,value)
                        if isinstance(unitId,list):
                            print "Updated Unit ID: %s|%s" % (sacliutil.printObjectPath(s,unitId.ref),sacliutil.printObjectID(unitId.ref[0]))
                        else:
                            print "Updated Unit ID: %s|%s" % (sacliutil.printObjectPath(s,[unitId.ref]),sacliutil.printObjectID(unitId.ref))
                    else:
                        p.print_help()
                        print "With update action provide --name=<name of attribute> and --value=<value of attribute> options."
                elif re.match('(?i)updateplatform?',arguments[0]):
                    if options.platform:
                        print "Updating platform on the following packages:"
                        for unitvo in s.updateUnitPlatform(options.id,options.platform,options.regex):
                            print "%s" % unitvo.ref
                    else:
                        p.print_help()
                        print "You need to provide --platform=<platform name>."
                elif re.match('(?i)addplatform?',arguments[0]):
                    if options.platform:
                        print "Adding platform to the following packages:"
                        for unitvo in s.addUnitPlatform(options.id,options.platform,options.regex):
                            print "%s" % unitvo.ref
                    else:
                        p.print_help()
                        print "You need to provide --platform=<platform name>."
                elif re.match('[Oo]verwrite',arguments[0]):
                    if options.pkgtype:
                        filetype = options.pkgtype
                    else:
                        filetype = sacliutil.detectPkgType(options.pkgfile)
                    if options.id and options.platform and filetype:
                        unitId = s.replaceUnit(options.pkgfile,filetype,options.id,options.platform)
                        print "Overwrote Unit: %s|%s" % (sacliutil.printObjectPath(s,[unitId]),sacliutil.printObjectID([unitId]))
                    else:
                        if not options.platform:
                            p.print_help()
                            print "You need to provide --platform with action overwrite"
                        elif not options.id:
                            p.print_help()
                            print "You need to provide --id with action overwrite"
                        elif not filetype:
                            p.print_help()
                            print "--pkgtype wasn't given and package couldn't detect the file type for %s" % options.pkgfile
                else:
                    p.print_help()
                    print "With --id provide the following actions: %s" % sacliutil.getActionList(action)
            else:
                p.print_help()
                print "With --id provide the following actions: %s" % sacliutil.getActionList(action)
        elif options.pkgfile:
            action = ['upload']
            if arguments:
                if re.match('[Uu]pload',arguments[0]):
                    filelist = glob.glob(options.pkgfile)
                    for filei in filelist:
                        if options.pkgtype:
                            filetype = options.pkgtype
                        else:
                            filetype = sacliutil.detectPkgType(filei)
                        if filetype and options.platform and options.folder:
                            if options.debug:
                                print "package type: %s" % filetype
                            if options.regex:
                                unitId = s.uploadUnit(filei,filetype,options.platform,options.folder,options.regex)
                            else:
                                unitId = s.uploadUnit(filei,filetype,options.platform,options.folder)
                            print "Created Unit: %s|%s" % (sacliutil.printObjectPath(s,[unitId]),sacliutil.printObjectID([unitId]))
                        else:
                            if not options.platform:
                                p.print_help()
                                print "You need to provide --platform with action upload."
                            elif not options.folder:
                                p.print_help()
                                print "You need to provide --folder with action upload."
                            elif not filetype:
                                p.print_help()
                                print "--pkgtype wasn't given and package couldn't detect the file type for %s" % filei
                else:
                    p.print_help()
                    print "Please provide an action: %s" % sacliutil.getActionList(action)
            else:
                p.print_help()
                print "Please provide an action: %s" % sacliutil.getActionList(action)
        elif options.pkgtypes:
            pkgtypes = s.getUnitTypes()
            print "List of valid SA package types"
            for pkgtype in pkgtypes:
                print "PackageType: %s" % pkgtype.typeName
                print "Description: %s" % pkgtype.description
                print "Valid Filetypes for %s:" % pkgtype.typeName
                for ftype in pkgtype.fileTypes:
                    print "%s: %s" % (ftype.typeName,ftype.description)
                print
        else:
            p.print_help()
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
    except SALib.IncorrectObjectRef,args:
        print "Update to unit failed: %s" % args


if __name__ == '__main__':
    try:
        main()
    except (SALib.AuthenticationFailed):
        print "package cmd is exiting because it couldn't authenticate the user."
    except (KeyboardInterrupt):
        print "package cmd is exiting because it received a Ctrl-C sequence from the keyboard."
    except OSError,args:
        print "OS had problems performing system call: %s" % args
    except SALib.RegExInvalid,args:
        print "Regular Expression is invalid the message was: %s" % args
    except SALib.InvalidSearchExpression,args:
        print "The Regular Expression you're using in one of your options aren't valid or the given expression isn't finding any SA Objects."
    except SALib.MultipleObjectRefsFound,args:
        print "Multiple Units specified.%s please specify just one" % args
    except AttributeError,args:
        print "The name attribute '%s' doesn't exist with specified package use action info to see a list of package attribute names" % (args,)
    except SALib.AuthorizationDeniedException,args:
        print "Either you don't have:"
        print "1. Permissions to run the action."
        print "2. You don't have read, write, or execute permission on the package."
        print "3. You haven't used --username=<username> to specify an authorized user to access the command."
        print "Here is the message given: %s" % args.message

