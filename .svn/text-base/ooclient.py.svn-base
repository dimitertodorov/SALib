from suds.client import Client
from suds.transport.http import HttpAuthenticated

url = 'https://owoo11x-ops-08.portal.webmd.com:8443/PAS/services/WSCentralService?wsdl'

class OOClient(object):

    def __init__(self, username, password, url=url):
        t = HttpAuthenticated(username=username, password=password)
        self.client = Client(url, transport=t)

    def run_flow(self, uuid, args):
        params = self.client.factory.create( 'ns0:WSRunParameters' )
        params.uuid = uuid
        params.startPaused = "False"
        params.trackStatus = "False"
        params.async = "True"
        params.flowInputs = []
        for (i,j) in args.iteritems():
            wsflow_input = self.client.factory.create( 'ns0:WSFlowInput' )
            wsflow_input.encrypted = "False"
            wsflow_input.name = i
            wsflow_input.value = j
            params.flowInputs.append( wsflow_input )
        return self.client.service.runFlow( params )

    def get_status(self, status):
        return self.client.service.getRunStatus( status )
