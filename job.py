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
    p = sacliutil.standardOptions("job --id=<jobid> [--<modifier options>] [ <action> ]")
    p.add_option('--id', help="Use to find SA jobs.")
    (options,arguments) = p.parse_args()
    s = sacliutil.getSALib(options.username,options.password,options.authfile)

    if options.debug:
        s.setDebug(1)
    if options.id:
        action = ['results']
        if arguments:
            if re.match('[Rr]esults?',arguments[0]):
                jobType = s.getJobResults(options.id)['type']
                jobResultDict = s.getJobResults(options.id)['hosts']
                hostKeys = jobResultDict.keys()
                hostKeys.sort()
                for host in hostKeys:
                    if jobType == 'server.script.run':
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
                    elif jobType == 'server.os.install':
                        if jobResultDict[host].error:
                            print "FAILED OS Provisioning on %s with JobID %s" % (host,options.id)
                            print "%s" % jobResultDict[host].error.message
                        else:
                            print "COMPLETED OS Provisioning on %s with JobID %s" % (host,options.id)
                            minusInstallProfile = re.sub(r'(-+[A-Za-z0-9. /]*-+\n)(.*\n)*(-+[A-Za-z0-9_. /]*-+\n)',\
                                                         '',\
                                                        jobResultDict[host].elemResultInfo[0].message.defaultMsg,re.MULTILINE)
                            print "%s" % minusInstallProfile
                    elif jobType == 'ogfs.script.run':
                        print "OGFS Host: %s" % host
                        print "JobRef: %s" % jobResultDict[host].jobInfo.ref
                        print "script: %s" % jobResultDict[host].jobInfo.script
                        print "start date: %s" % time.strftime("%a %b %d %H:%M:%S %Z %Y",time.localtime(jobResultDict[host].jobInfo.startDate))
                        print "end date: %s" % time.strftime("%a %b %d %H:%M:%S %Z %Y",time.localtime(jobResultDict[host].jobInfo.endDate))
                        print "parameters: %s" % jobResultDict[host].jobInfo.args.parameters
                        print "timeout: %s" % jobResultDict[host].jobInfo.args.timeOut
                        print "workingDir: %s" % jobResultDict[host].jobInfo.args.workingDir
                        print "stdout: %s" % jobResultDict[host].jobOutput.tailStdout
                    elif jobType == 'program_apx.execute':
                        print "OGFS Host: %s" % host
                        print "JobRef: %s" % jobResultDict[host].jobInfo.ref
                        print "version: %s" % jobResultDict[host].jobInfo.version
                        print "apx: %s" % jobResultDict[host].jobInfo.APX
                        print "start date: %s" % time.strftime("%a %b %d %H:%M:%S %Z %Y",time.localtime(jobResultDict[host].jobInfo.startDate))
                        print "end date: %s" % time.strftime("%a %b %d %H:%M:%S %Z %Y",time.localtime(jobResultDict[host].jobInfo.endDate))
                        print "parameters: %s" % jobResultDict[host].jobInfo.args.parameters
                        print "timeout: %s" % jobResultDict[host].jobInfo.args.timeOut
                        print "workingDir: %s" % jobResultDict[host].jobInfo.args.workingDir
                    elif jobType == 'server.swpolicy.remediate':
                        job_id = string.atol(options.id)
                        j = s.getJobResultsMap(job_id)
                        print "Software Policy JobID %s: %s" % (options.id, s.getJobResults(options.id)['hosts'][options.id])
                        for server_id, job_results in j['host_progress_dic'].iteritems():
                            print "%s: %s" % (s.getServerRefs(server_id)[0], job_results['status'])
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
        print "job cmd is exiting because it couldn't authenticate the user."
    except (KeyboardInterrupt):
        print "job cmd is exiting because it received a Ctrl-C sequence from the keyboard."
    except OSError,args:
        print "OS had problems performing system call: %s" % args
    except SALib.RegExInvalid,args:
        print "Regular Expression is invalid the message was: %s" % args
    except SALib.JobTypeNotImplemented,args:
        print "Job Type %s is not supported yet." % args
    except SALib.JobStillInProgress,args:
        print "Job ID %s is still running..." % args
    except SALib.NoObjectRefFound,args:
        print "Job ID %s was not found." % args
