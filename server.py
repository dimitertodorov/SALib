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
    p = sacliutil.standardOptions("server --id=<identifier> [--<modifier options>] [ <action> ]")
    p.add_option('--id', help="")
    p.add_option('--serverscript', help="Use to run a server script.")
    p.add_option('--customfield', help="Use to list or set a customfield.")
    p.add_option('--attribute', help="Use to set a server attribute, use info action to see attribute.")
    p.add_option('--value', help="Use to set a customfield value.")
    p.add_option('--days', help="Use to specify number of days to go back when viewing server history.")
    p.add_option('--weeks', help="Use to specify number of weeks to go back when viewing server history.")
    p.add_option('--dvcid',action="store_true", help="Use to view device id.")
    p.add_option('--customer',help="Specify a servers belonging to a facility.")
    p.add_option('--newcustomer',help="Use to assign servers to a new customer name/id. Used with assign action.")
    p.add_option('--facility',help="Specify a group of servers belonging to a facility.")
    p.add_option('--spolicy',help="Specify a software policy name for servers attached to them.")
    p.add_option('--servername', help="new server name, use with rename.")
    p.add_option('--sgmembers', help="list out servers that belong to a device group.")
    p.add_option('--caname', help="Use with server setca (Set Custom Attribute)")
    p.add_option('--value', help="Use with server setca (Set Custom Attribute)")
    (options,arguments) = p.parse_args()
    s = sacliutil.getSALib(options.username,options.password,options.authfile)

    if options.debug:
        s.setDebug(1)
    if options.id or options.facility or options.customer or options.spolicy or options.sgmembers:
        action = ['info','policystatus','list','history','updatecustomfield','showcustomfields','assign','getca','setca','clean','rename','commtest']
        if options.id and not (options.facility or options.customer or options.spolicy or options.sgmembers):
            serverRefs = s.getServerRefs(options.id,options.regex)
        elif options.facility and not (options.id or options.customer or options.spolicy or options.sgmembers):
            serverRefs = s.getServerRefsByFacility(options.facility,options.regex)
        elif options.customer and not (options.id or options.facility or options.spolicy or options.sgmembers):
            serverRefs = s.getServerRefsByCustomer(options.customer,options.regex)
        elif options.spolicy and not (options.id or options.facility or options.customer or options.sgmembers):
            serverRefs = []
            for spolicy,serverlist in s.getServerRefsBySoftwarePolicy(options.spolicy,options.regex).iteritems():
                serverRefs = serverRefs + serverlist
        elif options.sgmembers and not (options.id or options.facility or options.customer or options.spolicy):
            serverRefs = s.getServerGroupInfo(options.sgmembers,options.regex)['devices']
        else:
            print "Incorrect options given, possibly incorrect combination or the options don't exist."
            p.print_help()
        try:
            if arguments:
                # if arguments[0] == 'info':
                if re.match('[Ii]nfo',arguments[0]):
                    for i in serverRefs:
                        print "ServerRef: %s" % i
                        sacliutil.print_serverinfo(s,'s.getServerInfo',i)
                        print
                elif re.match('[Pp]olicystatus',arguments[0]):
                    policyStates = s.getPolicyAttachableStatesByServerRefs(serverRefs)
                    for sref in serverRefs:
                        print "ServerRef: %s" % sref
                        for policystate in policyStates:
                            if sref.id == policystate.policyAttachable.id:
                                policy = policystate.policyAssociation.policy
                                direct = policystate.policyAssociation.direct
                                remediated = policystate.policyAssociation.remediated
                                attached = policystate.policyAssociation.attached
                                dvcgroup = policystate.policyAssociation.deviceGroups
                                print "policy:%s direct:%s remediated:%s attached:%s dvcgroup:%s" % (policy,direct,remediated,attached,dvcgroup)
                        print
                elif re.match('(?i)list$',arguments[0]):
                    for i in serverRefs:
                        print "%s" % i
                elif re.match('(?i)history$',arguments[0]):
                    if options.days:
                        for i in serverRefs:
                            print "Server Name: %s" % i.name
                            for j in s.getServerHistorybyDays(i,string.atol(options.days)):
                                print "%s" % re.sub('[{}]','',"%s" % j)
                        #print "%s" % options.days
                        print
                    elif options.weeks:
                        for i in serverRefs:
                            print "Server Name: %s" % i.name
                            for j in s.getServerHistorybyWeeks(i,string.atol(options.weeks)):
                                print "%s" % re.sub('[{}]','',"%s" % j)
                        print
                    else:
                        p.print_help()
                        print "With [--days=<num of days> or --weeks=<num of weeks]"
                elif re.match('(?i)updatecustomfields?',arguments[0]):
                    if options.customfield:
                        results = s.setServerCustomFieldsByServerRefs(serverRefs,options.customfield,options.value,options.regex)
                        serverKeys = results.keys()
                        serverKeys.sort()
                        for server in serverKeys:
                            cfKeys = results[server].keys()
                            cfKeys.sort()
                            cfs = results[server]
                            for cf in cfKeys:
                                print "updated %s -> %s: oldvalue=%s newvalue=%s" % (server,cf,cfs[cf]['oldvalue'],cfs[cf]['newvalue'])  
                    else:
                        print "Must provide --customfield and --value option."
                elif re.match('(?i)updateattribute?',arguments[0]):
                    if options.attribute and options.value:
                        print "updated servers:"
                        for updated_svo in s.setServerAttributeByServerRefs(serverRefs,options.attribute,options.value,options.regex):
                            print "%s" % (updated_svo.ref)  
                    else:
                        print "Must provide --attribute and --value option."
                elif re.match('(?i)showcustomfields?',arguments[0]):
                    serverCustomFields = s.getServerCustomFieldsByServerRefs(serverRefs,options.customfield,regex=options.regex)
                    for server in serverCustomFields.keys():
                        print "%s" % server
                        for customfield in serverCustomFields[server]:
                            key = customfield.iterkeys().next()
                            print "%s: %s" % (key,customfield[key])
                        print
                elif re.match('(?i)assign',arguments[0]):
                    if options.newcustomer:
                        customer_ref = s.getCustomerRefs(options.newcustomer, options.regex)
                        if len(customer_ref) < 1:
                            p.print_help()
                            print "No Customer found."
                        elif len(customer_ref) > 1:
                            p.print_help()
                            print "Multiple Customers found, only one can be specified."
                        else:
                            serverGenerator = s.assignCustomerToServerByServerRefs(serverRefs,options.newcustomer,options.regex)
                            for server in serverGenerator:
                                print "%s assigned to customer %s" % server # server is a tuple returned by serverGenerator...
                    else:
                        print "Must provide --newcustomer with action assign."
                        p.print_help()
                elif re.match('(?i)getca?',arguments[0]):
                    servercas = s.getCustomAttributesOnServerByServerRefs(serverRefs)
                    for serverca in servercas.keys():
                        print "%s" % serverca
                        for ca in servercas[serverca].keys():
                            if not re.match('^__OPSW.*',ca):
                                print "%s : %s" % (ca,servercas[serverca][ca])
                        print
                elif re.match('(?i)setca?',arguments[0]):
                    if options.caname:
                        serverlist = s.setCustomAttributesOnServerByServerRefs(serverRefs,options.caname,options.value)
                        print "Updated Server CA:"
                        for server in serverlist:
                            print "%s" % server
                        print
                    else:
                        p.print_help()
                        print "You need to either provide --caname=<name> and --value=value with action setca."
                elif re.match('(?i)clean$',arguments[0]):
                    print "Cleaning server name (i.e. striping whitespace before and after the name.):"
                    for servervo in s.getServerValueObjectsByServerRefs(serverRefs,options.regex):
                        servervo.name = servervo.name.strip()
                        print "%s" % s.updateServerVO(servervo).ref
                elif re.match('(?i)rename$',arguments[0]):
                    if len(serverRefs) < 1:
                        raise SALib.NoObjectRefFound,options.id
                    elif len(serverRefs) > 1:
                        raise SALib.MultipleObjectRefsFound,options.server
                    servervo = s.getServerValueObjectsByServerRefs(serverRefs,options.regex)[0]
                    servervo.name = options.servername
                    print "Renamed %s to %s" % (serverRefs[0].name,s.updateServerVO(servervo).ref.name)
                elif re.match('(?i)commtest$',arguments[0]):
                    print "%s" % s.serverCommTest(serverRefs)
                else:
                    p.print_help()
                    print "Provide the action: %s" % sacliutil.getActionList(action)
            else:
                p.print_help()
                print "Provide the action: %s" % sacliutil.getActionList(action)
        except SALib.NoServerRefFound,sref:
            print "ERROR: Couldn't find %s." % sref
        except SALib.MultipleServerRefsFound,sref:
            print "ERROR: Multiple Servers found: %s, specify only one server for this operation." % sref
        except SALib.NullSearchValue,sref:
            print "ERROR: Empty Search Value given."
        except SALib.MultipleObjectRefsFound,sref:
            print "ERROR: Multiple Servers found: %s, specify only one server for this operation." % sref
        except SALib.NoObjectRefFound,ref:
            print "Server or pattern '%s' was not found." % ref
        except SALib.NullSearchValue:
            print "Specified a blank value or space."
    else:
        p.print_help()



if __name__ == '__main__':
    try:
        main()
    except (SALib.AuthenticationFailed):
        print "server cmd is exiting because it couldn't authenticate the user."
    except (KeyboardInterrupt):
        print "server cmd is exiting because it received a Ctrl-C sequence from the keyboard."
    except OSError,args:
        print "OS had problems performing system call: %s" % args
    except SALib.RegExInvalid,args:
        print "Regular Expression is invalid the message was: %s" % args
