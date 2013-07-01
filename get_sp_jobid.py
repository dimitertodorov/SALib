#!/opt/opsware/bin/python2

import os
import re
import simplejson as json
import string
import sys
import time
from optparse import OptionParser
import SALib
import sacliutil
import getpass

def get_sp_jobid(s, jobid, server):
    #
    # convert jobid into a long type
    #
    sp_jobid_dict = {}
    job_id = string.atol(jobid)
    j_result = s.getJobResultsMap(job_id)
    sref = s.getServerRefs(server)[0]
    sp_jobid_dict['server_id'] = "%s" % sref.id
    # The map function takes a structure returned by pytwist and rearranges the data structure.
    sp_jobid_dict['job_id'] = "%s" % dict(map(lambda x: [x[1], x[0]],\
            j_result['device_dict']["%s" % sref.id + "L"]['sessions']))['opsware.reconcile']
    return "%s" % json.dumps(sp_jobid_dict)

#
# Gets the Software Policy ID kicked off by a OS provisioning Job and
# returns a JSON blob with server and software policy job id.
#
def main():
    p = sacliutil.standardOptions("")
    p.add_option('--jobid', help="OS Sequence Job ID from HPSA.")
    p.add_option('--server', help="Server ID or Name.")
    (options,arguments) = p.parse_args()
    s = sacliutil.getSALib(options.username,options.password,options.authfile)

    if options.debug:
        s.setDebug(1)
    if options.jobid and options.server:
        print "%s" % get_sp_jobid(s, options.jobid, options.server)
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
