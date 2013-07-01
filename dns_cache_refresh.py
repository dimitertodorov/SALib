#!/opt/opsware/bin/python2

#
# First version
# John Yi 06/29/2010

import sys
import time
import getpass
sys.path.append('/opt/opsware/pylibs2')

from pytwist import *
from pytwist.com.opsware.compliance.sco import AuditTaskRef
from pytwist.com.opsware.compliance.sco import SnapshotTaskRef
from pytwist.com.opsware.script import ServerScriptRef
from pytwist.com.opsware.server import ServerRef
from pytwist.com.opsware.script import ServerScriptJobArgs
from pytwist.com.opsware.job import JobSchedule
from pytwist.com.opsware.job import PastScheduledDateException
from pytwist.com.opsware.job import JobIsScheduledException
from pytwist.com.opsware.fido import AuthenticationException


def print_usage():
	print "usage: dns_zone_detect.py <DataCenter>"

def getTwistService():
	# Should do user authentications and the like at some later point
	ts = twistserver.TwistServer()
	return ts

def isSnapshotResultThere(device_ids,snapshot_id,twist):
	sstRef = SnapshotTaskRef(snapshot_id)
	sstService = twist.compliance.sco.SnapshotTaskService
	ssrService = twist.compliance.sco.SnapshotResultService
	ssrServerIds = map(lambda x: ssrService.getSnapshotResultVO(x).server.id,
					sstService.getSnapshotResults(sstRef))
	for j in device_ids:
		if j not in ssrServerIds:
			return False
	return True

def removeAllSnapshotResults(snapshot_id,twist):
	sstRef = SnapshotTaskRef(snapshot_id)
	sstService = twist.compliance.sco.SnapshotTaskService
	ssrService = twist.compliance.sco.SnapshotResultService
	for i in sstService.getSnapshotResults(sstRef):
		ssrService.remove(i)	

def createJobNotification(twist):
	from pytwist.com.opsware.job import JobNotification
	fs = twistserver.FidoServer(twist)
	user_email = fs.UserFacade.getExtendedUserVO().emailAddress
	jobNotify = JobNotification()
	jobNotify.onFailureOwner = user_email
	jobNotify.onSuccessOwner = user_email
	jobNotify.onFailureRecipients = [user_email] 
	jobNotify.onSuccessRecipients = [user_email]
	return jobNotify
	
def runSnapshotSpecification(snapshot_id,username,jobNotify,twist):
	jobStarted = False
	time_offset = 3
	while not jobStarted:
		sstref = SnapshotTaskRef(snapshot_id)
		sstService = twist.compliance.sco.SnapshotTaskService
		jobSchedule = JobSchedule()
		jobSchedule.startDate = int(time.time()+ time_offset)
		try:
			jobId = sstService.startSnapshot(sstref,username,jobNotify,jobSchedule).id
			jobStarted = True
		except PastScheduledDataException:
			print "Snapshot Specification run (%s) is being rescheduled" % \
				sstService.getSnapshotTaskVO(sstref).name 
			jobStarted = False 
			time_offset = time_offset + 1
	return jobId

def runAuditTask(audit_id,username,jobNotify,twist):
	jobStarted = False
	time_offset = 3
	while not jobStarted:
		atref = AuditTaskRef(audit_id)
		atService = twist.compliance.sco.AuditTaskService
		jobSchedule = JobSchedule()
		jobSchedule.startDate = int(time.time()+ 4)
		try:
			jobId = atService.startAudit(atref,username,jobNotify,jobSchedule).id
			jobStarted = True
		except PastScheduledDateException: 
			print "Audit Task (%s) is being rescheduled" % \
				atService.getAuditTaskVO(atref).name 
			jobStarted = False 
			time_offset = time_offset + 1
	return jobId
	# arService = twist.compliance.sco.AuditResultService

def runOGFSScript(ogfsscript_id,username,jobNotify,devices,twist):
	jobStarted = False
	time_offset = 3
	while not jobStarted:
		ogfsref = OGFSScriptRef(ogfsscript_id)
		ogfsService = twist.compliance.sco.AuditTaskService
		ogfsJobArgs = OGFSScriptJobArgs()
		ogfsJobArgs.workingDir = "/"
		ogfsJobArgs.timeOut = 60
		tmpParam = ''
		for i in devices:
			tmpParam = tmpParam + "%s " % i
		ogfsJobArgs.parameters = tmpParam.strip()
		jobSchedule = JobSchedule()
		jobSchedule.startDate = int(time.time()+ time_offset)
		try:
			jobId = ogfsService.startOGFSScript(	ogfsref,
								ogfsJobArgs,
								username,
								jobNotify,
								jobSchedule).id
			jobStarted = True
		except PastScheduledDateException: 
			print "OGFS Script (%s) is being rescheduled" % \
				ogfsService.getOGFSScriptVO(ogfsref).name 
			jobStarted = False 
			time_offset = time_offset + 1
	return jobId

def runServerScript(script_id,username,jobNotify,devices,scriptArgs,twist,timeout=10):
	jobStarted = False
	time_offset = 5
	while not jobStarted:
		ssref = ServerScriptRef(script_id)
		ssService = twist.script.ServerScriptService
		ssJobArgs = ServerScriptJobArgs()
		ssJobArgs.targets = map(lambda x: ServerRef(x),devices)
		ssJobArgs.timeOut = timeout
		ssJobArgs.parameters = scriptArgs
		jobSchedule = JobSchedule()
		jobSchedule.startDate = int(time.time() + time_offset)
		try:
			jobId = ssService.startServerScript(	ssref,
								ssJobArgs,
								username,
								jobNotify,
								jobSchedule).id
			jobStarted = True
		except PastScheduledDateException:
			print "Server Script (%s) is being rescheduled" % \
				ssService.getServerScriptVO(ssref).name 
			jobStarted = False 
			time_offset = time_offset + 5
	return jobId

def checkJobFinished(timeout,loop_count,job_id,twist):
	time.sleep(timeout)
	from pytwist.com.opsware.job import JobRef
	jobref = JobRef(job_id)
	jobService = twist.job.JobService
	for i in range(loop_count):
		try:
			jobProgress = jobService.getProgress(jobref)
			if not hasattr(jobProgress,'active'):
				return True
		except JobIsScheduledException:
			print "Job %s is waiting to be scheduled on loop count %d" % (job_id,loop_count)
		time.sleep(timeout)
	return False

def removeAllAuditResults(audit_id,twist):
	atref = AuditTaskRef(audit_id)
	atService = twist.compliance.sco.AuditTaskService
	arService = twist.compliance.sco.AuditResultService
	for i in atService.getAuditResults(atref):
		arService.remove(i)

def filesHasDifferences(audit_id,twist):
	atref = AuditTaskRef(audit_id)
        atService = twist.compliance.sco.AuditTaskService
        arService = twist.compliance.sco.AuditResultService
	auditResult = atService.getAuditResults(atref)
	# Make sure we only have one auditResult
	if len(auditResult) > 1:
		return True
	if arService.getAuditResultVOs(auditResult)[0].nonCompliantObjectCount > 0:
		return True
	return False

def refreshDNScache(zone):
	print "Refreshing Bind DNS cache...."
	if not checkJobFinished(5,10,runServerScript(script_ids['bind'],
				username,createJobNotification(ts),
				bind_devices,zone,ts),ts):
			print "Server Script still running, exiting...."
			sys.exit(1)
	print "Refreshing Windows DNS cache...."
	if not checkJobFinished(5,10,runServerScript(script_ids['windns'],
				username,createJobNotification(ts),
				dc_devices,zone,ts),ts):
			print "Server Script still running, exiting...."
			sys.exit(1)



if __name__ == '__main__':

	if len(sys.argv) <= 1:
		print_usage()	
		sys.exit(1)

	#
	# Global Constants
	# Setting pre-defined snapshot_task and audit_task ids
	#
	
	if sys.argv[1] == 'iad1':
		# snapshot_task_id = 360005L
		# audit_task_id = 470005L

		# Eventually I'll be changing all of this hardcoded stuff by placing them into
		# server groups and referencing the scripts by name.
		# ns03x-ops-08 and ns04x-ops-08
		bind_devices = [187170005L,187180005L]
		#
		# dc01x-ops-03.portal.webmd.com
		#
		dc_devices = [172710001L]

		#
		# BIND_Test_RNDC and MSDNS_CACHE_FLUSH_TEST
		script_ids = {'bind':12300005L,'windns': 12900005L} 


		# sysops_BIND_ZoneRefresh_CacheFlush and sysops_MSDNS_ZoneRefresh_CacheFlush
		# script_ids = {'bind':10500005L,'windns': 10200005L} 
	elif sys.argv[1] == 'phx1':
		snapshot_task_id = 0L
		audit_task_id = 0L
		bind_devices = [172230004L,172160004L]
	elif sys.argv[1] == 'all':
		# All the devices in IAD1 and PHX1
		# bind_devices = [187170005L,187180005L,172230004L,172160004L]
		bind_devices = [187170005L]
		# dc_devices = [179050005L,172840005L,184300005L,81290005L,
		# 		173990004L,174000004L,180680004L,180690004L]

		# Eventually I'll be changing all of this hardcoded stuff by placing them into
		# server groups and referencing the scripts by name.
		# ns03x-ops-08 and ns04x-ops-08
		# bind_devices = [187170005L,187180005L]
		#
		# dc01x-ops-03.portal.webmd.com
		#
		dc_devices = [172710001L]

		#
		# BIND_Test_RNDC and MSDNS_CACHE_FLUSH_TEST
		# script_ids = {'bind':12300005L,'windns': 12900005L} 

		# sysops_BIND_ZoneRefresh_CacheFlush and sysops_MSDNS_ZoneRefresh_CacheFlush
		script_ids = {'bind':10500005L,'windns': 10200005L} 

	else:
		print_usage()

	#
	# Create our handles to the twister and fidoserver (User and Group APIs
	# hidden from the UAPI)
	#
	ts = getTwistService()
# Authentication is not needed if it's running in the OGFS.
	username=raw_input("Username: ")
#	password=getpass.getpass()	
#	try:
#		ts.authenticate(username=username,password=password)
#	except AuthenticationException:
#		print "Unable to authenticate user %s" % username
#		sys.exit(1)
	refreshDNScache(sys.argv[2])
	print "End of DNS Refresh"
