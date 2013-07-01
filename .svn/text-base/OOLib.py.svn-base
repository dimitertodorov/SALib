#!/opt/opsware/bin/python2

import sys
sys.path.append('/opt/opsware/SALib')
sys.path.append('/opt/opsware/pylibs2')

from pytwist import twistserver
import SALib

s = SALib.SALib()
ts = twistserver.TwistServer()
fs = twistserver.FidoServer(ts)


from SOAPpy import Config, HTTPTransport, SOAPAddress, WSDL
from SOAPpy.Types import faultType
from keyczar import keyczar
import os
import string
import base64

wsdlFile = 'https://owoo11x-ops-08.portal.webmd.com:8443/PAS/services/WSCentralService?wsdl'
keystore = '/var/opt/opsware/crypto/oo/keystore'
authfile = '/var/opt/opsware/crypto/oo/pwdfiles/svcoo.pwd'
retry = 3 # Number of times to retry a call
#
# OO flow to track SA OS Provisioning Jobs
#
# uuid = 'f95d695-35e9-4d50-bc36-bc4f690755fc'

class OOSoapCallFailed(Exception):
    pass

class myHTTPTransport(HTTPTransport):
    username = None
    passwd = None
    @classmethod
    def setAuthentication(cls,u,p):
        cls.username = u
        cls.passwd = p

    def call(self, addr, data, namespace, soapaction=None, encoding=None,http_proxy=None, config=Config):
        if not isinstance(addr, SOAPAddress):
            addr=SOAPAddress(addr, config)
        if self.username != None:
            addr.user = self.username+":"+self.passwd
        return HTTPTransport.call(self, addr, data, namespace, soapaction,encoding, http_proxy, config)
        
def setupSoapClient(authfile,keystore,wsdlFile):
    afd = file(authfile,'r')
    kz = keyczar.Crypter.Read(keystore)
    (username,password) = string.split(kz.Decrypt(afd.read().strip()),':')
    myHTTPTransport.setAuthentication(username, password)
    return WSDL.Proxy(wsdlFile, transport=myHTTPTransport)

def createAuthFile(username,password,authfile=authfile,keystore=keystore):
    afd = file(authfile,'w')
    kz = keyczar.Crypter.Read(keystore)
    ciphertxt = kz.Encrypt(username + ":" + password)
    afd.write(ciphertxt)
    os.chmod(authfile,0400)

def createFlowInputArgs(args):
    #
    # take a dictionary and convert it into soap arguments for OO flow
    #
    argList = []
    for arg in args.keys():
        argElement = {'name':arg,'value':args[arg]}
        argList.append(argElement)
    return argList

def launchOOFlow(uuid,args,authfile=authfile,keystore=keystore,wsdlFile=wsdlFile):
    soapArgs = createFlowInputArgs(args)
    server = setupSoapClient(authfile,keystore,wsdlFile)
    return server.runFlow( {'async':True,'flowInputs':soapArgs,'trackStatus':False,'uuid':uuid} )

def makeSoapCall(soapOperation,args,authfile=authfile,keystore=keystore,wsdlFile=wsdlFile):
    server = setupSoapClient(authfile,keystore,wsdlFile)
    soapcall = eval('server.%s' % soapOperation)
    return soapcall(args)

def getFlowProgress(runID,position=None,authfile=authfile,keystore=keystore,wsdlFile=wsdlFile,retry=retry):
    #
    # ugly Soap object parsing.
    #
    progress = {}
    stepDetails = {}
    status = None
    server = setupSoapClient(authfile,keystore,wsdlFile)
    while not status:
        try:
            status = server.getRunStatus({'runID':runID,'statusCursor':{'cursorPosition':position}})
        except faultType,args:
            if retry != 0:
                retry = retry - 1
                # uncomment to debug
                # print "Inside retry: %s" % retry
                continue
            else:
                raise OOSoapCallFailed,args
    progress['currentStep'] = status.runHandle['statusCursor']['cursorPosition']
    if len(status.steps) != 0:
        stepDetails['flowName'] = status.steps[-1:][0].flowName
        stepDetails['childRuns'] = status.steps[-1:][0].childRuns
        stepDetails['endTime'] = status.steps[-1:][0].endTime
        stepDetails['name'] = status.steps[-1:][0].name
        stepDetails['runStepLevel'] = status.steps[-1:][0].runStepLevel
        stepDetails['startTime'] = status.steps[-1:][0].startTime
        stepDetails['stepResponse'] = status.steps[-1:][0].stepResponse
        progress['stepDetails'] = stepDetails
    else:
        progress['stepDetails'] = None
    progress['runResponse'] = status.runResponse
    return progress


#if __name__ == '__main__':
#    (username,password) = string.split(base64.b64decode(key),':')
#    myHTTPTransport.setAuthentication(username, password)
#    server = WSDL.Proxy(wsdlFile, transport=myHTTPTransport)
#    retobj = server.runFlow(   {'async' : True,'flowInputs' : \
#       [{'name' : 'username','value' : os.environ['LOGNAME']}],'startPaused' : False,'trackStatus' : False,'uuid' : "0fbcdd17-fe52-4955-8a07-b2356a314fea" }   )
#    print "History ID: %d" % long(string.atol(retobj['runID']) - 1)
#    print "User email address: %s" % fs.UserFacade.getExtendedUserVO().emailAddress