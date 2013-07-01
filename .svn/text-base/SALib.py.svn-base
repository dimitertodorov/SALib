#!/opt/opsware/bin/python2

import bisect
import cPickle
import errno
import getpass
import glob
import os
import re
import sre_constants
import socket
import string
import subprocess
import sys
import time
import types

if not re.match('win',sys.platform):
    import pwd

if not re.match(r'win.*',sys.platform):
    sys.path.append('/opt/opsware/pylibs2')

from sets import Set
from pytwist import twistserver 
from pytwist import unitio 
from coglib import certmaster


from pytwist.twistserver import NotAuthenticatedException


from pytwist.com.opsware.acm import ApplicationInstanceRef, CMLRef, CMLVO,  \
                                    ConfigurationRef, ConfigurationVO, PlatformConstraintException

from pytwist.com.opsware.apx import APXRef, ProgramAPXJobArgs

from pytwist.com.opsware.common import DataAccessEngineCommunicationException, IllegalValueException,           \
                                        NotFoundException, OpswareException, OpswareSystemException,            \
                                        PackageRepositoryCommunicationException, SpokeCommunicationException,   \
                                        UniqueNameException

from pytwist.com.opsware.compliance.sco import AuditTaskRef, SnapshotTaskRef

from pytwist.com.opsware.custattr import NoSuchFieldException, VirtualColumnVO

from pytwist.com.opsware.device import DeviceGroupRef, DeviceGroupVO, PlatformRef

from pytwist.com.opsware.fido import ACLConstants, AuthenticationException, AuthorizationDeniedException,   \
                                        FolderACL, Operation, UserRoleRef

from pytwist.com.opsware.folder import FolderRef, NotInFolderException

from pytwist.com.opsware.job import JobInfoVO, JobIsScheduledException, JobNotification,    \
                                    JobRef, JobSchedule, PastScheduledDateException

from pytwist.com.opsware.locality import CustomerRef, FacilityRef

from pytwist.com.opsware.osprov import InstallProfileRef, OSSequenceRef

from pytwist.com.opsware.pkg import AppInstallerRef, BuildCustomizationScriptRef, CustomFieldUnitRef,   \
                                    ExecutableRef, RPMRef, RelocatableZIPRef, ServerModuleResultRef,    \
                                    ServerSnapshotResultRef, SoftwareRef, UnitVO, UnknownPkgRef, ZIPRef

from pytwist.com.opsware.pkg.aix import APARRef, BaseFilesetRef, UpdateFilesetRef, LPPRef

from pytwist.com.opsware.pkg.hpux import DepotRef, FilesetRef, PatchProductRef, ProductRef

from pytwist.com.opsware.pkg.windows import HotfixRef, MSIRef, PatchMetaDataRef, ServicePackRef,    \
                                            UpdateRollupRef, WindowsPatchRef, WindowsUtilityRef

from pytwist.com.opsware.pkg.solaris import SolPatchClusterRef, SolPkgInstanceRef, SolPkgRef, SolResponseFileRef

# Not Available in HPSA 7.50.0x
# from pytwist.com.opsware.pkg.solaris import SolPatchBundleRef, SolPatchRef


from pytwist.com.opsware.script import OGFSScriptJobArgs, OGFSScriptRef, ScriptJobOutput, ServerScriptJobArgs,  \
                                        ServerScriptRef, ServerScriptVO, ServerScriptVersion, UniqueVersionStringException

from pytwist.com.opsware.search import Filter, InvalidSearchGrammarException, InvalidSearchTypeException, SearchException

from pytwist.com.opsware.server import ServerRef

from pytwist.com.opsware.swmgmt import ActionArgument, AnalyzeArgument, InstallableAttachableEntry,                 \
                                        PatchPolicyRef, RebootArgument, RemediateGlobalParamSet,                    \
                                        RemediateScriptParamSet, SoftwarePolicyItemData, SoftwarePolicyRPMItemData, \
                                        SoftwarePolicyRef, SoftwarePolicyScriptItemData, SoftwarePolicyVO,          \
                                        SoftwareUninstallJobArgument, StageArgument, WindowsPatchPolicyRef

from pytwist.com.opsware.virtualization import HypervisorRef



# from pytwist.com.opsware.exception import TwistException

# from pytwist.com.opsware.serialization import TwistConnectorInvocationException




try:
    from pytwist.com.opsware.serialization import TwistInstantiationException
except ImportError,args:
    print "Couldn't import TwistInstantiationException, problem was: %s" % args.args

unitRefs = (    AppInstallerRef, BuildCustomizationScriptRef, CustomFieldUnitRef, DepotRef, ExecutableRef,\
                HotfixRef, LPPRef, MSIRef, PatchMetaDataRef, RPMRef, ServerModuleResultRef, ServerSnapshotResultRef,\
                ServicePackRef, SolPatchClusterRef, SolPkgInstanceRef, SolPkgRef, SolResponseFileRef,\
                UnknownPkgRef, UpdateRollupRef, WindowsUtilityRef, ZIPRef   )

softwarePolicyItemDataRefs = (  APARRef, AppInstallerRef, BaseFilesetRef, ConfigurationRef, CMLRef, ExecutableRef,\
                                FilesetRef, HotfixRef, MSIRef, PatchPolicyRef, PatchProductRef, ProductRef,\
                                RelocatableZIPRef, RPMRef, ServerModuleResultRef, ServerScriptRef,\
                                ServerSnapshotResultRef, ServicePackRef, SoftwarePolicyRef,\
                                SolPatchClusterRef, SolPkgInstanceRef, UpdateFilesetRef, UpdateRollupRef,\
                                WindowsPatchPolicyRef, WindowsPatchRef, ZIPRef  ) 

customAttributeRefs = (DeviceGroupRef,CustomerRef,FacilityRef,ServerRef)#InstallProfileRef,SoftwarePolicyRef
#
# Email account where email messages will say they're from.
#
_email_owner = 'opsware@webmd.net'

# Helper method to get credentials for the twist service.
def getToken(username=None,password=None,duration=-1):
    try:
        if not username:
            username=raw_input("Username: ")
        if not password:
            password=getpass.getpass()
        ts = twistserver.TwistServer()
        ts.authenticate(username=username,password=password)
        token = str(ts._makeCall('com/opsware/fido/AuthenticationService','authenticate',[username,password,duration]))
    except AuthenticationException,args:
        print "Unable to authenticate user %s" % username
        raise AuthenticationFailed
    return token
#   Example:
#       (username,password) = SALib.getCredential()
#       salib = SALib(username,password)

# Helper method to get security context for twist service.
# This may not be needed because the twistserver object automatically
# attempts to find the valid certificates on the box that it is being run.
# Try just connecting with the hostname.
def getSecurityContext(certificate_file):
    try:
        return certmaster.getContext(certificate_file)
    except ValueError:
        print "Invalid certificate file: %s" % 'agent.srv'
# HP SA security certificates are located in /var/opt/opsware/crypto
# Users should try to use the least privileged certficate i.e. agent.srv
#   Example:
#       ctx = SALib.getSecurityContext('/var/opt/opsware/crypto/agent/agent.srv')
#       salib = SALib(username,password)

class SASearchObjectNotFound(Exception):
    pass

class SAAttributeNotFound(Exception):
    pass
                        
class MultipleSAAttributesFound(Exception):
    pass

class MultipleServerVOs(Exception):
    pass

class ServerVONotFound(Exception):
    pass

class MultipleSnapshotTaskFound(Exception):
    pass

class NoSnapshotTaskFound(Exception):
    pass

class MultipleOGFSScriptFound(Exception):
    pass

class NoOGFSScriptFound(Exception):
    pass

class MultipleServerRefsFound(Exception):
    pass

class NoServerRefFound(Exception):
    pass

class MultipleDeviceGroupRefsFound(Exception):
    pass

class NoDeviceGroupRefFound(Exception):
    pass

class MultipleFolderRefsFound(Exception):
    pass

class MultipleUserGroupFound(Exception):
    pass

class NoFolderRefFound(Exception):
    pass

class NoObjectRefFound(Exception):
    pass

class NoCustomAttributeFound(Exception):
    pass

class MultipleObjectRefsFound(Exception):
    pass

class IncorrectObjectRef(Exception):
    pass

class FolderNotEmpty(Exception):
    pass

class ObjectAlreadyExists(Exception):
    pass

class NullSearchValue(Exception):
    pass

class UnknownSearchType(Exception):
    pass

class UnknownSearchAttribute(Exception):
    pass

class UnknownPolicyItemType(Exception):
    pass

class InvalidSearchExpression(Exception):
    pass

class DeletingRootFolderNotAllowed(Exception):
    pass

class NoTargetsSpecified(Exception):
    pass

class JobTypeNotImplemented(Exception):
    pass

class JobStillInProgress(Exception):
    pass

class NotInFolder(Exception):
    pass

class TwistMethodCallError(Exception):
    pass

class SoftwareRepositoryUploadFailed(Exception):
    pass

class SoftwareRepositoryDownloadFailed(Exception):
    pass

class PermissionDenied(Exception):
    pass

class RegExInvalid(Exception):
    pass

class AuthenticationFailed(Exception):
    pass

class SerializationException(Exception):
    pass

class PlatformMismatchException(Exception):
    pass

class NotSoftwarePolicyItem(Exception):
    pass

class InvalidArgs(Exception):
    pass

class InvalidObjectRef(Exception):
    pass

class DuplicatePolicyItemFound(Exception):
    pass

class NameNotSpecified(Exception):
    pass

class NoCustomFieldFound(Exception):
    pass

class VersionStringConflict(Exception):
    pass

# class PytwistCallException(TwistException):
#   pass

#
# class Singleton(object) :
#         """ A Pythonic Singleton """
#         def __new__(cls, *args, **kwargs):
#                 if ' _inst' not in vars(cls) :
#                         cls. _inst = super(Singleton, cls) . __new__(cls, *args, **kwargs)
#                 return cls. _inst

#
# I'm using the Borg non-DP as outlined by Alex Martelli, Alex A. Naanou. There's a lot of discussion
# on whether or not to even use a Monostate DP vs an outright a module.
# However I feel I can implement SALib cleaner as a class rather than a module.  -John 06/09/2010
#
class Borg(object) :
    _shared_state = { }
    def __new__(cls, *a, **k):
        obj = object. __new__(cls, *a, **k)
        obj. __dict__ = cls. _shared_state
        return obj

class Translator:
    pattern = re.compile(
    r"""\@   # Starting with '@'
    (?:\w+)? # an optional object specifier
    ((?:\.)|(\.[0-9]+\.))?  # followed by an optional '.'
    [\w-]+      # a string
    \@       # ending with another @
    """, re.X)

    #custattr_scope = {
    #    "customer" : ctx.getCustomerRefs,
    #    "facility" : ctx.getFacilityRefs,
    #   "software_policy" : self.ctx.getSoftwarePolicyRefs,
    #   "device_group" : self.ctx.getDeviceGroupRefs,
    #   "os_profile" : self.ctx.getInstallProfileRefs,
    #   "server" : self.ctx.getServerRefs
    #   }
    custattr_scope = [
        "customer", #: ctx.getCustomerRefs,
        "facility", # : ctx.getFacilityRefs,
        "software_policy", # : self.ctx.getSoftwarePolicyRefs,
        "device_group", # : self.ctx.getDeviceGroupRefs,
        "os_profile", # : self.ctx.getInstallProfileRefs,
        "server", # : self.ctx.getServerRefs
       ] #}
    

    def __init__(self, ctx=None):
        if isinstance(ctx,SALib):
            self.ctx = ctx
        else:
            self.ctx = SALib()
        self.__objref = None

    def sub(self, ObjRef, text):
        if isinstance(ObjRef,ServerRef):
            self.__objref = ObjRef # create a private instance variable so that we can pass this to __repl
            return self.pattern.sub(self.__repl, text)
        else:
            raise InvalidObjectRef,"Need to pass a ServerRef argument."

    def __repl(self, matchobj):
        # matchstr is the string inside the @at signs@
        matchstr = matchobj.group(0)[1:-1]
        if string.find(matchstr, ".") == -1:
        # new style, no dot needed as of feynman
        # the key name is the whole string between the @'s
            return self.__getCA(self.__objref,matchstr,True)
        # if we're here, it's the old style @.key@ or @scope.key@
        if len(string.split(matchstr,'.')) == 3:
            (obj_spec, id, key) = string.split(matchstr, '.')
            if not re.match("^[0-9]+$",id):
                raise TypeError
            if obj_spec == '': # @.<key>
                return self.__getCA(self.__objref,key,False)
            elif obj_spec in self.custattr_scope:
                if obj_spec == 'facility':
                    if int(id) == -1:
                        sVO = self.ctx.getTwister().server.ServerService.getServerVO(self.__objref)
                        return self.__getCA(sVO.facility,key,False)
                    else:
                        self.__checkForIncorrectId(id,self.ctx.getFacilityRefs)
                        return self.__getCA(self.ctx.getFacilityRefs(id)[0],key,False)
                elif obj_spec == 'customer':
                    if int(id) == -1:
                        sVO = self.ctx.getTwister().server.ServerService.getServerVO(self.__objref)
                        return self.__getCA(sVO.customer,key,False)
                    else:
                        self.__checkForIncorrectId(id,self.ctx.getCustomerRefs)
                        return self.__getCA(self.ctx.getCustomerRefs(id)[0],key,False)
                elif obj_spec == 'server':
                    if int(id) == -1:
                        return self.__getCA(self.__objref,key,False)
                    else:
                        self.__checkForIncorrectId(id,self.ctx.getServerRefs)
                        return self.__getCA(ctx.getServerRefs(id)[0],key,False)
                elif obj_spec == 'device_group':
                    return self.__noAutoFillCustomAttribute(self.ctx.getDeviceGroupRefs,id,key)
                elif obj_spec == 'os_profile':
                    return self.__noAutoFillCustomAttribute(self.ctx.getInstallProfileRefs,id,key)                
                elif obj_spec == 'software_policy':
                    return self.__noAutoFillCustomAttribute(self.ctx.getSoftwarePolicyRefs,id,key)
#	    fn = self.custattr_dispatch[obj_spec]
#	    return fn(self.ctx, key) or ''
            else:
                # accept a tag with '.' as part of the custom attribute name if it isn't in custattr_scope.
                return self.__getCA(self.__objref,key,True)
        else:
            return self.__getCA(self.__objref,matchstr,True)
            
    def __noAutoFillCustomAttribute(self,fn,id,key):
        if int(id) == -1:
            raise NoObjectRefFound
        else:
            objreflist = fn(id)
            if len(objreflist) == 0:
                raise NoObjectRefFound
            else:
                return self.ctx.getCustomAttribute(objreflist[0],key,False) or ''
    
    def __checkForIncorrectId(self,id,fn):
        if len(fn(id)) == 0:
            raise NoObjectRefFound
    
    def __getCA(self,objref,key,scope):
        try:
            return self.ctx.getCustomAttribute(objref,key,scope)
        except NoCustomAttributeFound:
            return "@" + key + "@"




_OBJECT_ATTRIBUTE_EXCLUDE = [ "__OPSW_CHANGED_ATTRS__", "dirtyAttributes", "ref" ]
_CLASS_ATTRIBUTE_EXCLUDE = {
#        "ServerVO" : [ "ref" ],
        "PhysicalDiskVO" : [ "device" ],
}

def _getObjectAsDict(obj):
    attrs = {}
    for k, v in obj.__dict__.items():
        if k in _OBJECT_ATTRIBUTE_EXCLUDE or k in _CLASS_ATTRIBUTE_EXCLUDE.get(obj.__class__.__name__, []):
            continue
        
        if isinstance(v, list) or isinstance(v, tuple):
            attrs[k] = [_getObjectAsDict(x) for x in v]
        
        elif isinstance(v, types.InstanceType):
            attrs[k] = _getObjectAsDict(v)
        
        else:
            attrs[k] = v
    
    return attrs




#
# When instantiating SALib you only need to provide the following:
# username,password, and host
# If you're not running the SALib in OGFS then it will automatically set
# the security context. If you have saved the certificate file in a non-standard location
# (i.e. not in /var/opt/opsware/crypto) then provide the certificate file by calling
# getSecurityContext helper method.
#
# example of most use cases:
# import SALib from SALib
# s = SALib(username='jyi',password='USAvsEngland2010',host='twistserver.portal.webmd.com')
#
# class SALib( Borg ) :
class SALib:
    __ts = None # __ts twist service handle
    __fs = None # both __fs and __ds are internal facade apis that are from a previous versions of SA and 
    __ds = None # subject to change. However they provide critical functionality so we need to use it.

    __version = None # SA Twist UAPI API version information
    __jobNotify = None # Internal jobNotify object needed to start HP SA jobs.
    __username = None

    __saAttributeList = {}
    __saSearchableTypes = None
    __debug = 0

    def __init__(self,username=None,password=None,host=None,__ts=None,ctx=None,token=None):
        if __ts is not None:
            self.__ts = __ts
        else:
            try:
                if token:
                    self.__ts = twistserver.TwistServer(host=host,ctx=ctx,token=token)
                else:
                    self.__ts = twistserver.TwistServer(host=host,ctx=ctx)
                if username is not None or password is not None:
                    self.__ts.authenticate(username,password)
                    self.__username = username
                else:
                    # Figure out username from OGFS LOGNAME environment variable.
                    if not re.match('win',sys.platform):
                        self.__username = pwd.getpwuid(os.getuid())[0]
                    elif token:
                        pass
                    else:
                        raise AuthenticationException,username
                #
                # This call is mainly to test and see if we have a bogus twist host
                # and if so throw an exception.
                #
                self.__version = self.__ts.shared.TwistConsoleService.getAPIVersion()
                self.__fs = twistserver.FidoServer(self.__ts)
                self.__ds = twistserver.DataAccessServer(self.__ts)
                self.__createJobNotification()
            except socket.gaierror:
                print "Twist host %s not found. Need to provide a valid twist hostname." 
                raise AuthenticationFailed
            except AuthenticationException:
                print "Unable to authenticate user %s" % username
                raise AuthenticationFailed
            except NotAuthenticatedException:
                print "Username and/or Password was not given."
                raise AuthenticationFailed
    
    def getTwister(self):
        return self.__ts

    
    # convenience methods to access twister services
    
    def __getSearchService(self):
        return self.getTwister().search.SearchService
    
    def __getServerService(self):
        return self.getTwister().server.ServerService
    
    def __getDeviceGroupService(self):
        return self.getTwister().device.DeviceGroupService
    
    def __getPlatformService(self):
        return self.getTwister().device.PlatformService
    
    def __getCustomerService(self):
        return self.getTwister().locality.CustomerService
    
    def __getFacilityService(self):
        return self.getTwister().locality.FacilityService
    
    def __getRealmService(self):
        return self.getTwister().locality.RealmService
    
    def __getLogicalVolumeService(self):
        return self.getTwister().storage.LogicalVolumeService
    
    def __getPhysicalDiskService(self):
        return self.getTwister().storage.PhysicalDiskService
    
    
    def __createJobNotification(self):
        user_email = self.__fs.UserFacade.getExtendedUserVO().emailAddress
        self.__jobNotify = JobNotification()
        self.__jobNotify.onFailureOwner = _email_owner
        self.__jobNotify.onSuccessOwner = _email_owner
        self.__jobNotify.onFailureRecipients = [user_email] 
        self.__jobNotify.onSuccessRecipients = [user_email]

    def __getSearchAttribute(self,object_type,Attr):
        #
        # This method is meant to find attributes in the format
        # SAObject.<attribute>
        # There are cases where it breaks from these conventions, so in those cases you
        # will need to add special attributes in __getSAObjectNameIdFilter
        #
        searchService = self.__ts.search.SearchService
        if not self.__saAttributeList.has_key(object_type):
            self.__saAttributeList[object_type] = searchService.getSearchableAttributes(object_type)
        return [ i for i in self.__saAttributeList[object_type] if re.match('[a-zA-Z]+%s' % Attr ,i) ]

    def __getSAObjectNameIdFilter(self,sa_types,saObject_name_id,name_attribute='\.name'):
        ss = self.__ts.server.ServerService
        searchService = self.__ts.search.SearchService
        filter = Filter()

        if self.__saSearchableTypes is None:
            self.__saSearchableTypes = searchService.getSearchableTypes()

        if sa_types not in self.__saSearchableTypes:
            raise SASearchObjectNotFound,sa_types

        #
        # Because of the short sighted way in which the attributes are named for each SA object
        # it is necessary to add any attributes that doesn't fit the usually
        # SAObject.name or SAObject.pK etc.
        # Put any unique attributes here. Note they need to be done in two places,
        # one is the strings and the other is for the ints and longs.
        #
        if type(saObject_name_id) == long or type(saObject_name_id) == int:
            if self.__getSearchAttribute(sa_types,"\.pK"):
                saObjectAttributePK = self.__getSearchAttribute(sa_types,"\.pK")
                filter.expression = '%s in %d' % (saObjectAttributePK[0],saObject_name_id)
                filter.objectType = sa_types
            elif "%s_oid" % sa_types in searchService.getSearchableAttributes(sa_types):
                sa_attribute = "%s_oid" % sa_types
                filter.expression = '%s EQUAL_TO %d' % (sa_attribute,saObject_name_id)
                filter.objectType = sa_types
            elif "%s_rc_id" % sa_types in searchService.getSearchableAttributes(sa_types):
                sa_attribute = "%s_rc_id" % sa_types
                filter.expression = '%s EQUAL_TO %d' % (sa_attribute,saObject_name_id)
                filter.objectType = sa_types
            else:
                raise SAAttributeNotFound,saObjectAttributePK
            return filter
        else:
            if re.match('[0-9]+L?',saObject_name_id):
                if self.__getSearchAttribute(sa_types,"\.pK"):
                    saObjectAttributePK = self.__getSearchAttribute(sa_types,"\.pK")
                    filter.expression = '%s in %d' % (saObjectAttributePK[0],string.atol(saObject_name_id))
                    filter.objectType = sa_types
                elif "%s_oid" % sa_types in searchService.getSearchableAttributes(sa_types):
                    sa_attribute = "%s_oid" % sa_types
                    filter.expression = '%s EQUAL_TO %d' % (sa_attribute,string.atol(saObject_name_id))
                    filter.objectType = sa_types
                elif "%s_rc_id" % sa_types in searchService.getSearchableAttributes(sa_types) and not self.__getSearchAttribute(sa_types,"\.pK"):
                    sa_attribute = "%s_rc_id" % sa_types
                    filter.expression = '%s EQUAL_TO %d' % (sa_attribute,string.atol(saObject_name_id))
                    filter.objectType = sa_types
                else:
                    raise SAAttributeNotFound,saObjectAttributePK
                return filter
            else:
                saObjectAttributeName = self.__getSearchAttribute(sa_types,name_attribute)
                if len(saObjectAttributeName) < 1:
                    raise SAAttributeNotFound,saObjectAttributeName
                if len(saObjectAttributeName) > 1:
                    raise MultipleSAAttributesFound,saObjectAttributeName
                filter.expression = '%s CONTAINS_WITH_WILDCARDS "%s"' % (saObjectAttributeName[0],saObject_name_id)
                filter.objectType = sa_types
                return filter

    def setDebug(self,debug):
        self.__debug = debug
        
    def callUAPI(self, service, method, *args):
        twist = self.__ts
        ServiceString = "twist.%s.%s" % (service,method)
        ObjectService = eval(ServiceString)
        args_str = ""
        for i in range(0,len(args)):
            if i == 0:
                args_str = "args[%d]" % i
            else:
                args_str = args_str + "," + "args[%d]" % i
        args_str = "(" + args_str + ")"
        return eval("ObjectService%s" % args_str)

    def __getObjectRefs(self,objects,service,sa_types,search_method,ObjRef=None,name_attribute='\.name'):
    # objects: Name of object to get either string name,id, or actually object itself
    # service: SA service interface (i.e. ts.server.ServerService)
    # sa_types: String of SA search types. (i.e. Listing given by ts.search.SearchService.getSearchableTypes() )
    # search_method: String of the search method to use. (i.e. ServerService.findServerRefs() )
    # name_attribute: String of the name attribute for the given object.(i.e. ServerVO.name, where the '\.name'to name_attribute)
    # ObjRef: SA Object Reference (i.e. ServerRef, SoftwarePolicyRef, OGFSScriptRef, etc.)
        Service = service 
        ObjectRefs = []
        if type(objects) == str:
            # convert into a list
            # and strip leading and tail spaces.
            objects = [ i.strip() for i in re.split('[,]',objects) ]
        #elif type(objects) == long or type(objects) == int:
        else:
            objects = [ objects ]
        for i in objects:
            if isinstance(i,ObjRef):
                ObjectRefs.append(i)
            else:
                filter = self.__getSAObjectNameIdFilter(sa_types,i,name_attribute)
                if self.__debug:
                    print "%s" % filter.expression
                    print "%s" % search_method
                objref = eval("Service.%s" % search_method)(filter)
                if self.__debug:
                    for i in objref: print "%s" % i 
                    print "len(objref): %d" % len(objref)
                    print [ i for i in objref ]
                if not len(objref) < 1: 
                    for i in objref: ObjectRefs.append(i)
        return ObjectRefs

    def __filteredListWithWildCards(self,matchString,ObjectList,attribute='name',wildcard_char='\*'):
        filteredList = []
        matchExpressions = matchString
        for matchExpression in re.split(',',matchExpressions):
            # print "match expression: %s" % matchExpression
            if re.search(wildcard_char,matchExpression):
                if re.search('/',matchExpression):
                    if matchExpression != '/':
                        # strip ending / from the matchExpression
                        if matchExpression.endswith('/'):
                            matchExpression = matchExpression[:-1]
                        (folderPath,matchExpression) = os.path.split(matchExpression)
                # since . matches all characters in regex we need to escape any real . in the matchExpression so that
                # it is not interpreted as any character.
                matchExpression = re.sub(r'(\.)',r'\.',matchExpression)
                matchExpression = re.sub(r'^(.*)$',r'^\1$',matchExpression)
                # matchExpression = re.sub('\*','[A-Za-z .0-9_()-]*',matchExpression)
                matchExpression = re.sub('\*','.*',matchExpression)
                if self.__debug:
                    print "match expression: %s" % matchExpression
                for s in ObjectList:
                    if re.match(matchExpression,eval("s.%s" % attribute)):
                        filteredList.append(s)
            else:
                for s in ObjectList:
                    if self.__debug:
                        print "objectref outside guard: %s" % s
                    if re.search('/',matchExpression):
                        if matchExpression != '/':
                            # strip ending / from the matchExpression
                            if matchExpression.endswith('/'):
                                matchExpression = matchExpression[:-1]
                            (folderPath,matchExpression) = os.path.split(matchExpression)
                        if self.__debug:
                            print "objectref: %s" % s
                            print "eval expression: %s" % eval("s.%s" % attribute)
                            print "match expression: %s" % matchExpression
                    if eval("s.%s" % attribute) == matchExpression:
                        if self.__debug:
                            print "matchExpression: %s" % matchExpression
                        filteredList.append(s)
                    elif re.match('[0-9]+L?',matchExpression):
                        matchID = long(matchExpression)
                        if matchID == s.idAsLong:
                            filteredList.append(s)
        filteredList.sort()
        return filteredList

    def __filteredListWithRegEx(self,matchString,ObjectList,attribute='name'):
        filteredList = []
        matchExpressions = matchString
        for matchExpression in re.split(',',matchExpressions):
            if re.search('/',matchExpression):
                # strip ending / from the matchExpression
                if matchExpression != '/':
                    if matchExpression.endswith('/'):
                        matchExpression = matchExpression[:-1]
                (folderPath,matchExpression) = os.path.split(matchExpression)
            if self.__debug:
                print "match expression: %s" % matchExpression
            for s in ObjectList:
                try:
                    if re.match(matchExpression,eval("s.%s" % attribute)):
                        filteredList.append(s)
                except sre_constants.error,args:
                    raise RegExInvalid,args
        filteredList.sort()
        return filteredList

    def __filterByFolderPath(self,objectString,objectService,searchType,findMethod,objectRef,regex,nameAttribute,listall=False):
        if type(objectString) == str:
            if regex:
                if re.search('/',objectString):
                    if objectString != '/':
                        (folderPath,matchString) = os.path.split(objectString)
                        matchString = folderPath
                        separateFpathAndFnode = False
                    else:
                        matchString = objectString
                        separateFpathAndFnode = True
                else:
                    matchString = '*'
                    separateFpathAndFnode = False
            else:
                matchString = objectString
                separateFpathAndFnode = True
            # Get the full list ObjectRefs to apply filters
            # print "matchString: %s" % matchString
            objRefs = self.__getObjectRefsbyPath(   getService=self.__ts.folder.FolderService,
                                                    findService=objectService,
                                                    getMethod='getFNode',
                                                    findMethod=findMethod,
                                                    sa_types=searchType,
                                                    objRef=objectRef,
                                                    object_path=matchString,
                                                    name_attribute=nameAttribute,
                                                    separateFpathAndFnode=separateFpathAndFnode )
            if listall:
                objectList = objRefs
            else:
                objectList = [ i for i in objRefs if isinstance(i,objectRef) ]
            if regex:
                return self.__filteredListWithRegEx(objectString,objectList)
            else:
                return self.__filteredListWithWildCards(objectString,objectList)
        else:
            objRefs = self.__getObjectRefsbyPath(   self.__ts.folder.FolderService,
                                                    objectService,
                                                    "getFNode",
                                                    findMethod,
                                                    searchType,
                                                    objectRef,
                                                    objectString,
                                                    nameAttribute   )
            # Filter the objRefs for only unit referenced objects. unitRefs is a tuple of all valid unit references.
            return [ i for i in objRefs if isinstance(i,objectRef) ]

    def __filterByName(self,objectString,objectService,searchType,findMethod,objectRef,regex,nameAttribute):
        if type(objectString) == str:
            if regex:
                # Get the full list ObjectRefs to apply filters
                objectList = self.__getObjectRefs(  '*',
                                                    objectService,
                                                    searchType,
                                                    findMethod,
                                                    objectRef,
                                                    nameAttribute   )
                return self.__filteredListWithRegEx(objectString,objectList)
            else:
                objectList = self.__getObjectRefs(  objectString,
                                                    objectService,
                                                    searchType,
                                                    findMethod,
                                                    objectRef,
                                                    nameAttribute   )
                return self.__filteredListWithWildCards(objectString,objectList)
        else:
            objectList = self.__getObjectRefs(  objectString,
                                                objectService,
                                                searchType,
                                                findMethod,
                                                objectRef,
                                                nameAttribute   )
            return objectList

    def getInstallProfileRefs(self,installosprofile,regex=False):
        if not installosprofile:
            raise NullSearchValue,"getInstallProfileRefs"
        if type(installosprofile) == str:
            if re.match('^[ \t]+$',installosprofile):
                raise NullSearchValue,"getInstallProfileRefs"
        return self.__filterByName( installosprofile,
                                    self.__ts.osprov.InstallProfileService,
                                    'os_node',
                                    'findInstallProfileRefs',
                                    InstallProfileRef,
                                    regex,
                                    '_node_rc_name'    )

    def getFacilityRefs(self,facility,regex=False):
        if not facility:
            raise NullSearchValue,"getFacilityRefs"
        if type(facility) == str:
            if re.match('^[ \t]+$',facility):
                raise NullSearchValue,"getFacilityRefs"
        return self.__filterByName( facility,
                                    self.__ts.locality.FacilityService,
                                    'facility',
                                    'findFacilityRefs',
                                    FacilityRef,
                                    regex,
                                    '_rc_name'    )


    def getServerRefs(self,servers,regex=False):
        if not servers:
            raise NullSearchValue,"getServerRefs"
        if type(servers) == str:
            if re.match('^[ \t]+$',servers):
                raise NullSearchValue,"getServerRefs"
        return self.__filterByName( servers,
                                    self.__ts.server.ServerService,
                                    'device',
                                    'findServerRefs',
                                    ServerRef,
                                    regex,
                                    '\.name'    )

    def getServerValueObjectsByServerRefs(self,serverRefs,regex=False):
        ss = self.__ts.server.ServerService
        return ss.getServerVOs(serverRefs)
    
    def updateServerVO(self,servervo):
        ss = self.__ts.server.ServerService
        return ss.update(servervo.ref,servervo,False,True)

    def getServerInfo(self,server_id_name):
        ss = self.__ts.server.ServerService
        if isinstance(server_id_name,ServerRef):
            sref = [ server_id_name ]
        else:
            sref = self.getServerRefs(server_id_name)
        if len(sref) > 1:
            raise MultipleServerRefsFound,sref
        if len(sref) < 1:
            raise NoServerRefFound,sref
        device_vo = ss.getServerVO(sref[0])
        serverInfo = {}
        for i in [ k for k in dir(device_vo) if not re.match('__[A-Za-z_-]+__',k) ]:
            serverInfo[i] = eval("device_vo.%s" % i)
        return serverInfo

    
    def getPolicyAttachableStates(self,server,regex):
        ss = self.__ts.server.ServerService
        if isinstance(server,ServerRef):
            srefs = [ server ]
        else:
            srefs = self.getServerRefs(server,regex)
        if len(srefs) < 1:
            raise NoServerRefFound,sref
        return ss.getPolicyAttachableStates(srefs)
    
    def getPolicyAttachableStatesByServerRefs(self,serverRefs):
        ss = self.__ts.server.ServerService
        if len(serverRefs) < 1:
            raise NoServerRefFound,"server(s)"
        return ss.getPolicyAttachableStates(serverRefs)

    def serverCommTest(self, server_refs):
        ss = self.__ts.server.ServerService
        if len(server_refs) < 1:
            raise NoServerRefFound,sref
        return ss.runAgentCommTest(server_refs)

    def __getDeviceGroupRefs(self,server_group,regex=False):
        if not server_group:
            raise NullSearchValue,"getDeviceGroupRefs"
        elif type(server_group) == str:
            if re.match('^[ \t]+$',server_group):
                raise NullSearchValue,"getDeviceGroupRefs"
        if type(server_group) == str:
            if regex:
                deviceGroupList = self.__getObjectRefs( '*',
                                                        self.__ts.device.DeviceGroupService,
                                                        "device_group",
                                                        "findDeviceGroupRefs",
                                                        DeviceGroupRef,
                                                        '\.shortName'   )
                return self.__filteredListWithRegEx(server_group,deviceGroupList)
            else:
                deviceGroupList = self.__getObjectRefs( server_group,
                                                        self.__ts.device.DeviceGroupService,
                                                        "device_group",
                                                        "findDeviceGroupRefs",
                                                        DeviceGroupRef,
                                                        '\.shortName'   )
                return self.__filteredListWithWildCards(server_group,deviceGroupList)
        else:
            deviceGroupList = self.__getObjectRefs( server_group,
                                                    self.__ts.device.DeviceGroupService,
                                                    "device_group",
                                                    "findDeviceGroupRefs",
                                                    DeviceGroupRef,
                                                    '\.shortName'   )
            return deviceGroupList

    def getDeviceGroupRefs(self,servergroup_id_name,regex=False):
        if not servergroup_id_name:
            raise NullSearchValue,"getDeviceGroupRefs"
        elif type(servergroup_id_name) == str:
            if re.match('^[ \t]+$',servergroup_id_name):
                raise NullSearchValue,"getDeviceGroupRefs"
        dgs = self.__ts.device.DeviceGroupService
        if isinstance(servergroup_id_name,DeviceGroupRef):
            sgref = [ servergroup_id_name ]
        else:
            sgref = []
            if type(servergroup_id_name) == list:
                servergroups = servergroup_id_name
            elif type(servergroup_id_name) == str:  
                servergroups = re.split(',',servergroup_id_name)
            elif type(servergroup_id_name) == int or long:  
                servergroups = self.__getDeviceGroupRefs(servergroup_id_name,regex)
            for servergroup in servergroups:
                if self.__debug:
                    print "Inside servergroups loop...."
                if type(servergroup) == str:
                    if re.search('/\w+(/\w+)?/?',servergroup):
                        servergroup = servergroup.strip()
                        if servergroup.startswith('/'):
                            if self.__debug:
                                print "servergroup before stripping leading '/': %s" % servergroup
                            servergroup = servergroup[1:]
                            if self.__debug:
                                print "servergroup after stripping leading '/': %s" % servergroup
                            if not re.search('^(Public|Private)',servergroup):
                            # Assume the caller was thinking of accessing the Public server group
                                servergroup = 'Public/' + servergroup
                        if servergroup.endswith('/'):
                            servergroup = servergroup[:-1]
                        #
                        # Crazy code to try and catch idiots who use / in the Server Group
                        # naming.
                        if re.search(r'\\/',servergroup):
                            servergroup = re.sub(r'\\/',r'\\',servergroup)
                            if self.__debug:
                                print "matching \/: %s" % servergroup
                        elif re.search(r'\\',servergroup):
                            servergroup = re.sub(r'\\',r'\\\\',servergroup)
                        #
                        # User has to escape the / character if used in the name. Once the / has been substituted
                        # within the name of the server group, we can get the appropriate servergroups and
                        # their paths.
                        #
                        (sgRelativePath,sg) = os.path.split(servergroup)
                        if self.__debug:
                            print "2nd sg: %s" % sg
                            print "2nd sgRelativePath: %s" % sgRelativePath
                        sgRelativePath = re.split('/',sgRelativePath)
                        #
                        # The next for loops will put the / back into the name so that we can now look for
                        # it using the getDeviceGroupByPath method.
                        #
                        for p in [sgRelativePath,sg]:
                            for i in range(0,len(p)):
                                if re.search(r'\\',p[i]):
                                    p[i] = re.sub(r'\\',r'/',p[i])
                                elif re.search(r'\\',p[i]):
                                    p[i] = re.sub(r'\\\\',r'\\',p[i])
                        if self.__debug:
                            print "sgRelativePath: %s" % sgRelativePath
                            print "sg: %s" % sg
                        try:
                            # sgref.append(dgs.getDeviceGroupByPath(SGpath))
                            if self.__debug:
                                print "sgRelativePath: %s" % sgRelativePath
                            if not sgRelativePath[0]:
                                # The means that sgRelativePath is empty in which case there is no path and no reason to filter out
                                # server groups by path. just return.
                                sgpathref = dgs.getDeviceGroupByPath([sg])
                                sgref.append(sgpathref)
                                break
                            else:
                                sgpathref = dgs.getDeviceGroupByPath(sgRelativePath)
                            if self.__debug:
                                print "sgpathref: %s" % sgpathref
                                print "servergroup: %s" % servergroup
                            sgRefListSet = Set(dgs.getChildren(sgpathref))
                            sgrefSet = Set(sgref)
                            if regex:
                                sgref = self.__filteredListWithWildCards(servergroup,list(sgrefSet.union(sgRefListSet)),True)
                            else:
                                sgref = self.__filteredListWithWildCards(servergroup,list(sgrefSet.union(sgRefListSet)))
                        except NotFoundException,sgref:
                            raise NoDeviceGroupRefFound,sgref
                    else:
                        #
                        # Looking for \\/ in the servergroup name will cause it not to be found. We have to
                        # put the / back and then look for it.
                        #
                        if re.search(r'\\/',servergroup_id_name):
                            servergroup_id_name = re.sub(r'\\/',r'/',servergroup_id_name)
                        sgref = self.__getDeviceGroupRefs(servergroup_id_name,regex)
                elif type(servergroup) == int or long:
                    sgref = self.__getDeviceGroupRefs(servergroup_id_name,regex)
        return sgref

    def getServerGroupInfo(self,servergroup_id_name,regex=False):
        dgs = self.__ts.device.DeviceGroupService
        sgref = self.getDeviceGroupRefs(servergroup_id_name,regex)
        if len(sgref) > 1:
            sgref = "%s" % [ re.sub('^[A-Za-z _-]+/','/', dgs.getDeviceGroupVO(i).fullName) for i in sgref ]
            raise MultipleDeviceGroupRefsFound,sgref
        if len(sgref) < 1:
            raise NoDeviceGroupRefFound,sgref
        device_group_vo = dgs.getDeviceGroupVO(sgref[0])
        serverGroupInfo = {}
        for i in [ k for k in dir(device_group_vo) if not re.match('__[A-Za-z_-]+__',k) ]:
            if i == "dynamicRule":
                if eval("device_group_vo.%s" % i):
                    serverGroupInfo[i] = eval("device_group_vo.%s.expression" % i)
                else:
                    serverGroupInfo[i] = None
            else:
                serverGroupInfo[i] = eval("device_group_vo.%s" % i)
        return serverGroupInfo

    def createServerGroup(self,SG,dvc_list=None,dGH='public',device_type='com.opsware.server.ServerRef',isDynamic=False,ruleExpression=None,objectType='device'):
        dgs = self.__ts.device.DeviceGroupService
        dvcGroupVO = DeviceGroupVO()
        if re.search('/',SG):
            if re.search('^/Private/%s' % self.__username,SG):
                SG = re.sub('^/Private/%s' % self.__username,'/Private',SG) 
            (SGPATH,newSG) = os.path.split(SG)
            parentSG = self.getDeviceGroupRefs(SGPATH)
            if not len(parentSG) == 1:
                print "ERROR: Multiple parent server groups %s. Please specify one." % parentSG
                sys.exit(1)
        else:
            if dGH == 'public':
                parentSG = dgs.getPublicRoot()
            elif dGH == 'private':
                parentSG = dgs.getPrivateRoot()
            newSG = SG
        if device_type == 'com.opsware.server.ServerRef' and dvc_list:
            server_list = self.getServerRefs(dvc_list)  
        else:
            server_list = []
        if self.__debug:
            print "parentSG: %s" % parentSG
        if isinstance(parentSG,list):
            dvcGroupVO.parent = parentSG[0]
        else:
            dvcGroupVO.parent = parentSG
        dvcGroupVO.shortName = newSG
        dvcGroupVO.dynamic = isDynamic
        if isDynamic:
            dynamicRule = Filter()
            dynamicRule.objectType = objectType 
            dynamicRule.expression = ruleExpression
            dvcGroupVO.dynamicRule = dynamicRule
        else:
            dvcGroupVO.devices = server_list
        try:
            newdvcGroupVO = dgs.create(dvcGroupVO)
        except UniqueNameException,SG:
            raise ObjectAlreadyExists,SG
        SGname = re.sub('^[A-Za-z _-]+/','/', newdvcGroupVO.fullName)
        print "ServerGroup Name: %s" % SGname 
        print "ServerGroup ID: %d" % newdvcGroupVO.ref.id
        print "Added these devices: %s" % dvc_list

    def removeServerGroup(self,SG):
        dgs = self.__ts.device.DeviceGroupService
        dvcGroupRef = self.getDeviceGroupRefs(SG)
        if len(dvcGroupRef) < 1:
            print "ERROR: No server groups to delete. Please specify at least one."
            raise NoDeviceGroupRefFound,SG
        for i in dvcGroupRef:
            dvcName = i.name
            dvcId = i.id
            dgs.remove(i)
            (parentGroup,removedGroup) = os.path.split(SG)
            print "Removed ServerGroup: %s/%s (DeviceGroupRef: %d)" % (parentGroup,dvcName,dvcId)

    def addServersToServerGroup(self,Servers,ServerGroup):
        dgs = self.__ts.device.DeviceGroupService
        sgref = self.getDeviceGroupRefs(ServerGroup)
        if not len(sgref) == 1:
            print "ERROR: Please specify one server group." % sgref
            raise MultipleDeviceGroupRefsFound,sgref
        srefs = self.getServerRefs(Servers)
        dvc_list = self.getServerGroupInfo(sgref[0])['devices']
        for i in srefs:
            if i in dvc_list:
                print "%s is already a member of %s" % (i.name,ServerGroup)
                srefs.remove(i)
        if srefs:
            dgs.addDevices(sgref[0],srefs)
            print "Added devices %s to %s" % ([i.name for i in srefs],sgref[0])
        else:
            print "No devices were added."

    def removeServersFromServerGroup(self,Servers,ServerGroup):
        dgs = self.__ts.device.DeviceGroupService
        sgref = self.getDeviceGroupRefs(ServerGroup)
        if not len(sgref) == 1:
            print "ERROR: Please specify one server group." % sgref
            raise MultipleDeviceGroupRefsFound,sgref
        srefs = self.getServerRefs(Servers)
        dvc_list = self.getServerGroupInfo(sgref[0])['devices']
        for i in srefs:
            if not i in dvc_list:
                print "%s is not a member of %s" % (i.name,ServerGroup)
                srefs.remove(i)
        if srefs:
            dgs.removeDevices(sgref[0],srefs)
            print "Removed device %s from %s" % ([i.name for i in srefs],sgref[0])
        else:
            print "No devices were removed."

    def printFolderObj(self,folder,recursive,type,regex=False,refname=None,firstRun=True):
        fs = self.__ts.folder.FolderService
        folderRefs = self.getFolderRefs(folder,regex)
        if refname and firstRun:
            if not regex:
                refname = re.sub(r'(\.)',r'\.',refname)
                refname = re.sub(r'^(.*)$',r'^\1$',refname)
                refname = re.sub('\*','.*',refname)
                if self.__debug:
                    print "refname after wildcard conv: %s"  % refname
        if type != '':
            ObjRef = eval(type)
        if recursive:
            for i in folderRefs:
                folderVO = fs.getFolderVO(i)
                fpath = fs.getFolderPaths([ i ])[0]
                for k in folderVO.members:
                    if fpath.path == '/':
                        if type == '' or isinstance(k,ObjRef):
                            if refname:
                                if re.match(refname,"%s" % k.name):
                                    print "%s%s" % (fpath.path,k)
                            else:
                                print "%s%s" % (fpath.path,k)
                        if isinstance(k,FolderRef):
                            self.printFolderObj([ k ],True,type,regex,refname,False)
                    else:
                        if type == '' or isinstance(k,ObjRef):
                            if refname:
                                if re.match(refname,"%s" % k.name):
                                    print "%s/%s" % (fpath.path,k)
                            else:
                                print "%s%s" % (fpath.path,k)
                        if isinstance(k,FolderRef):
                            self.printFolderObj([ k ],True,type,regex,refname,False)
        else:
            for i in folderRefs:
                folderVO = fs.getFolderVO(i)
                fpath = fs.getFolderPaths([ i ])[0]
                for k in folderVO.members:
                    if fpath.path == '/':
                        if type == '' or isinstance(k,ObjRef):
                            if refname:
                                if re.match(refname,"%s" % k.name):
                                    print "%s%s" % (fpath.path,k)
                            else:
                                print "%s%s" % (fpath.path,k)

                    else:
                        if type == '' or isinstance(k,ObjRef):
                            if refname:
                                if re.match(refname,"%s" % k.name):
                                    print "%s/%s" % (fpath.path,k)
                            else:
                                print "%s/%s" % (fpath.path,k)
                        
    def getFolderObj(self,folder,recursive,type,regex=False,refname=None,firstRun=True):
        fs = self.__ts.folder.FolderService
        folderRefs = self.getFolderRefs(folder,regex)
        if refname and firstRun:
            if not regex:
                refname = re.sub(r'(\.)',r'\.',refname)
                refname = re.sub(r'^(.*)$',r'^\1$',refname)
                refname = re.sub('\*','.*',refname)
                if self.__debug:
                    print "refname after wildcard conv: %s"  % refname
        if type != '':
            ObjRef = eval(type)
        if recursive:
            for i in folderRefs:
                folderVO = fs.getFolderVO(i)
                for k in folderVO.members:
                    if type == '' or isinstance(k,ObjRef):
                        if refname:
                            if re.match(refname,"%s" % k.name):
                                yield k
                        else:
                            yield k
                    if isinstance(k,FolderRef):
                        for i in self.getFolderObj([ k ],True,type,regex,refname,False):
                            yield i
        else:
            for i in folderRefs:
                folderVO = fs.getFolderVO(i)
                for k in folderVO.members:
                    if type == '' or isinstance(k,ObjRef):
                        if refname:
                            if re.match(refname,"%s" % k.name):
                                yield k
                            else:
                                yield k

    def getObjectPath(self,FolderRef_list,recursive=False):
        fs = self.__ts.folder.FolderService
        object_path = {}
        if recursive:
            obj_list = []
            for i in FolderRef_list:
                obj_list.append([i,fs.getPath(i)])
                for j in fs.list(i,True,''):
                #
                # This iterates thru the list of all folder objects for a given folder.
                #
                    obj_list.append([j[-1:][0],j])
                    for l in obj_list:
                    #
                    # This iterates thru the list of list of folder objects.
                    #
                        for m in l[1]:
                            #
                            # This iterates thru the list of folder objects that make up the path.
                            #
                            if m.name.startswith('/'):
                                tmp_str = ''
                            else:
                                tmp_str = tmp_str + '/' + m.name
                        object_path[l[0]] = tmp_str
            #
            # object_path is a dict value that coresponds to objectref as the key to object path as the value.
            #
        else:
            for i in FolderRef_list:
                try:
                    if self.isHPSA9x() or not isinstance(i,ConfigurationRef):
                        if self.__debug:
                            print "%s" % i
                        pathList = fs.getPath(i)
                        for j in pathList:
                            if j.name.startswith('/'):
                                tmp_str = ''
                            else:
                                tmp_str = tmp_str + '/' + j.name
                        object_path[i] = tmp_str 
                    else:
                        object_path[i] = "%s" % i
                except AuthorizationDeniedException:
                    raise AuthorizationDeniedException
                except NotInFolderException:
                    raise NotInFolder,i
        return object_path

    def getObjectStringPath(self,FolderRef_list,recursive=False,type=''):
        fs = self.__ts.folder.FolderService
        for i in FolderRef_list:
            if i in [ fs.getRoot() ]:
                rootFolderVO = fs.getFolderVO(i)
                if recursive:
                    for k in rootFolderVO.members:
                        for l in fs.list(k,recursive,type):
                            obj_path_dict = self.getObjectPath(l[-1:])
                            (obj_path,obj) = os.path.split(obj_path_dict[l[-1:][0]])
                            print "/%s" % l[-1:][0]
                else:
                    for k in rootFolderVO.members:
                        print "/%s" % k
            else:
                for j in fs.list(i,recursive,type):
                    obj_path_dict = self.getObjectPath(j[-1:])
                    (obj_path,obj) = os.path.split(obj_path_dict[j[-1:][0]])
                    print "%s/%s" % (obj_path,j[-1:][0])

    def createFolder(self,folder_path):
        fs = self.__ts.folder.FolderService
        if type(folder_path) == str:
            folder_list = re.split(',',folder_path)
            for i in folder_list:
                if self.__debug:
                    print "folder item: %s" % i
                    print "root folder: %s" % fs.getRoot() 
                i.strip()
                if i.startswith('/'):
                    i = i[1:]   
                if i.endswith('/'):
                    i = i[:-1]
                fVO = fs.createPath(fs.getRoot(),re.split('/',i))
                (ParentFolderPath,newFolder) = os.path.split(i) 
                if ParentFolderPath == '/':
                    print "Create Folder: %s%s" % (ParentFolderPath,fVO.ref)
                else:
                    print "Create Folder: %s/%s" % (ParentFolderPath,fVO.ref)
                    if self.__debug:
                        print "ParentFolderPath: %s" % ParentFolderPath 
                        print "fVO.ref: %s" % fVO.ref
        elif type(folder_path) == list:
            for j in folder_path:
                if type(j) == str:
                    if j.startswith('/'):
                        j = j[1:]   
                    if j.endswith('/'):
                        j = j[:-1]  
                    fVO = fs.createPath(fs.getRoot(),re.split('/',j))
                    (ParentFolderPath,newFolder) = os.path.split(j) 
                    if ParentFolderPath == '/':
                        print "Create Folder: %s%s" % (ParentFolderPath,fVO.ref)
                    else:
                        print "Create Folder: %s/%s" % (ParentFolderPath,fVO.ref)
                else:
                    raise TypeError 

    def removeFolder(self,folder_path,recursive=False):
        fs = self.__ts.folder.FolderService
        fpath = {}
        if type(folder_path) == str or list:
            fRef_list = self.getFolderRefs(folder_path)
            if fs.getRoot() in fRef_list:
                raise DeletingRootFolderNotAllowed,fs.getRoot()
            if not recursive:
                for i in fRef_list:
                    if fs.list(i,False,''):
                        (ParentFolder,folder) = os.path.split(self.getObjectPath([ i ])[i])
                        if ParentFolder == '/':
                            folderStr = "%s%s" % (ParentFolder,i)
                        else:
                            folderStr = "%s/%s" % (ParentFolder,i)
                        raise FolderNotEmpty,folderStr
            if self.__debug:
                for i in fRef_list:
                    print "fRef_element: %s" % i
            if recursive:
                fpath = self.getObjectPath(fRef_list,True)
            else:
                fpath = self.getObjectPath(fRef_list,False)
            fnode_list = list(fs.bulkRemove( fRef_list ))
            fnode_list.sort()
            fnode_list.reverse()
            for k in fnode_list:
                (ParentFolder,removedFolder) = os.path.split(fpath[k])
                if ParentFolder == '/':
                    print "Removed: %s%s" % (ParentFolder,k) 
                else:
                    print "Removed: %s/%s" % (ParentFolder,k) 
        else:
            raise TypeError 

    def getFolderObjectRefs(self,object_path):
        if not object_path:
            raise NullSearchValue,"getFolderObjectRefs"
        elif re.match('^[ \t]+$',object_path):
            raise NullSearchValue,"getFolderObjectRefs"
        fs = self.__ts.folder.FolderService
        if type(object_path) == str:
            if object_path.startswith('/'): object_path = object_path[1:]
            object_path = object_path.strip()
            object_path = re.split('/',object_path)
            return fs.getFNode(object_path)
        else:
            raise TypeError, object_path

    def __getObjectRefsbyPath(self,getService,findService,getMethod,findMethod,sa_types,objRef,object_path,name_attribute='\.name',getChildrenMethod='getChildren',separateFpathAndFnode=True):
        Service = getService 
        getObjectRefMethod = eval("Service.%s" % getMethod)
        getChildrenMethod = eval("Service.%s" % getChildrenMethod)
        ObjectRefs = []
        # print "eval(Service.%s  getMethod)" % getMethod
        #
        # In SA the two main objects that use file/folder/path concepts are folders (including the objects within them)
        # and servergroups. This method handles getting SA objects contained in folders.
        #
        # print "In __getObjectRefsbyPath"
        # print "object_path before split with ,: %s" % object_path
        if type(object_path) == str:
            object_path = re.split(',',object_path)
            # print "object_path: %s" % object_path
            for i in object_path:
                if re.search('/',i):
                    # print "before strip i: %s" % i
                    i = i.strip()
                    # print "after strip i: %s" % i
                    # print "separateFpathAndFnode=%s; i = %s" % (separateFpathAndFnode, i)
                    if separateFpathAndFnode and i == '/':
                        # print "getObjectRefMethod on '/' results: %s" % getObjectRefMethod([i])
                        # ObjectRefs.append(getObjectRefMethod([i]))
                        relativePath = [ i ]
                        objectName = ''
                    elif separateFpathAndFnode and i != '/':
                        (relativePath,objectName) = os.path.split(i)
                        # print "Before split relativePath: %s" % relativePath 
                        relativePath = re.split('/',relativePath)
                        if relativePath[0] == '':
                            relativePath[0] = '/'
                        while '' in relativePath:
                            relativePath.remove('')
                        # print "After split relativePath: %s" % relativePath 
                        # convert relativePath from a string into a list of strings
                    elif not separateFpathAndFnode and ( i == '/' or i != '/'):
                        relativePath = i
                        relativePath = re.split('/',relativePath)
                        if relativePath[0] == '':
                            relativePath[0] = '/'
                        while '' in relativePath:
                            relativePath.remove('')
                        objectName = 'a'
                    # elif not separateFpathAndFnode and i != '/':
                        # relativePath = [ i ]
                        # objectName = ''
                        # print "relativePath: %s" % relativePath 
                        # print "objectName: %s" % objectName 
                        # print "relativePath as a list of strings: %s" % relativePath
                    try:
                        #
                        # The two objects that use file and folder type concepts is folder refs
                        # and servergroup refs. The getObjectRefMethod really uses
                        # getFNode for folders.
                        #
                        # print "Inside getObjectRefMethod: %s" % relativePath
                        relativePathRef = getObjectRefMethod(relativePath)
                        # print "relativePathRef: %s" % relativePathRef
                        # print "objectName: %s" % objectName 
                        #
                        
                        if objectName == '':
                            # objectName being empty means this is the root folder
                            ObjectRefs = [ relativePathRef ]
                        else:
                            # Using python set operations to remove duplicates.
                            # print "Entering Set Operations."
                            TempObjectRefsSet = Set(getChildrenMethod(relativePathRef))
                            # print "TempObjectRefsSet: %s." % TempObjectRefsSet
                            ObjectRefsSet = Set(ObjectRefs)
                            ObjectRefs = list(ObjectRefsSet.union(TempObjectRefsSet))   
                        # ObjectRefs.append( getObjectRefMethod(re.split('/',i)) )
                        # print "ObjectRefs: %s" % ObjectRefs
                    except NotFoundException,args:
                        if not i.startswith('/'):
                            j = '/' + i
                        raise NoObjectRefFound,i
                else:
                    # print "In the didn't find / objRef: %s" % i
                    tempRefs = self.__getObjectRefs(    i,
                                                        findService,
                                                        sa_types,
                                                        findMethod,
                                                        ObjRef=objRef,
                                                        name_attribute=name_attribute   )
                    ObjectRefs = ObjectRefs + tempRefs
        elif type(object_path) == long or type(object_path) == int:
            return self.__getObjectRefs(    object_path,
                                            findService,
                                            sa_types,
                                            findMethod,
                                            ObjRef=objRef,
                                            name_attribute=name_attribute   )
        elif type(object_path) == list:
            for j in object_path:
                if type(j) == str:
                    j = j.strip()
                    if j == '/':
                        ObjectRefs.append(  getObjectRefMethod([ j ])  )
                    else:
                        if j.startswith('/'):
                            j = j[1:]   
                        if j.endswith('/'):
                            j = j[:-1]
                        try:
                            ObjectRefs.append( getObjectRefMethod(re.split('/',j)) )
                        except NotFoundException,args:
                            if not j.startswith('/'):
                                j = '/' + j
                            raise NoObjectRefFound,j
                elif isinstance(j,objRef): 
                    ObjectRefs.append( j )
                else:
                    try:
                        ObjectRefs.append(self.__getObjectRefs( j,
                                                                findService,
                                                                sa_types,
                                                                findMethod,
                                                                ObjRef=objRef,
                                                                name_attribute=name_attribute   )[0])
                    except NotFoundException,args:
                        if not i.startswith('/'):
                            j = '/' + i
                        raise NoObjectRef,j
        elif isinstance(object_path,objRef): 
            ObjectRefs.append( object_path )
        else:
            raise TypeError,object_path 
        # print "About to return ObjectRefs: %s" % ObjectRefs
        return ObjectRefs 

    def getFolderRefs(self,folder_path,regex=False,listall=False):
        fs = self.__ts.folder.FolderService
        if not folder_path:
            raise NullSearchValue,"getFolderRefs"
        if type(folder_path) == str:
            if re.match('^[ \t]+$',folder_path):
                raise NullSearchValue,"getFolderRefs"
        return self.__filterByFolderPath(   objectString=folder_path,
                                            objectService=self.__ts.folder.FolderService,
                                            searchType='folder',
                                            findMethod='findFolderRefs',
                                            objectRef=FolderRef,
                                            regex=regex,
                                            nameAttribute='\.name',
                                            listall=listall )

    def getFolderInfo(self,folder):
        fs = self.__ts.folder.FolderService
        folderref = self.getFolderRefs(folder)
        if len(folderref) > 1:
            folderref = "%s" % [ re.sub('^[A-Za-z _-]+/','/', fs.getFolderVO(i).name) for i in folderref ]
            raise MultipleFolderRefsFound,folderref
        if len(folderref) < 1:
            raise NoFolderRefFound,folderref
        folder_vo = fs.getFolderVO(folderref[0])
        FolderInfo = {}
        for i in [ k for k in dir(folder_vo) if not re.match('__[A-Za-z_-]+__',k) ]:
            FolderInfo[i] = eval("folder_vo.%s" % i)
        return FolderInfo

    def getUserRoleRefs(self,userRoleName):
        urs = self.__ts.fido.UserRoleService
        if not userRoleName:
            raise NullSearchValue,"getUserRoleRefs"
        elif type(userRoleName) == str:
            if re.match('^[ \t]+$',userRoleName):
                raise NullSearchValue,"getUserRoleRefs"
        return self.__getObjectRefs(    userRoleName,
                                        self.__ts.fido.UserRoleService,
                                        "user_role",
                                        "findUserRoleRefs",
                                        UserRoleRef,
                                        '\.roleName'    )


    def __FolderACLs(self, mode, Folder, Permission, UserGroup, recursive, propagateListAccessUp):
        fs = self.__ts.folder.FolderService
        userRoles = self.getUserRoleRefs(UserGroup)
        folderrefs = self.getFolderRefs(Folder)
        folder_acls = []
        #
        # make sure Permission is a string or a string with comma seperated items 
        #
        if not type(Permission) == str:
            raise TypeError
        permissions = [ i.strip() for i in re.split('[,]',Permission) ]
        #
        # replace permissions with the ones used by com.opsware.fido
        #
        tmp_perm = []
        for i in permissions:
            if re.match('^[rR]',i):
                tmp_perm.append(ACLConstants.READ_ACCESS_LEVEL)
            elif re.match('^[wW]',i):
                tmp_perm.append(ACLConstants.WRITE_ACCESS_LEVEL)
            elif re.match('^[lL]',i):
                tmp_perm.append(ACLConstants.LIST_ACCESS_LEVEL)
            elif re.match('^[eExX]',i):
                tmp_perm.append(ACLConstants.EXECUTE_ACCESS_LEVEL)
            elif re.match('^[pP]',i):
                tmp_perm.append(ACLConstants.PERMISSION_MGMT_ACCESS_LEVEL)
        permissions = tmp_perm
        #
        # Create list of folder_acls
        #
        for i in userRoles:
            for j in folderrefs:
                for k in permissions:
                    if self.__debug:
                        print "role: %s" % i
                        print "folder: %s" % j
                        print "accessLevel: %s" % k
                    folder_acl = FolderACL()
                    folder_acl.role = i
                    folder_acl.folder = j
                    folder_acl.accessLevel = k
                    folder_acls.append(folder_acl)
        if mode == 'add':
            fs.addFolderACLs(folder_acls,recursive,propagateListAccessUp)
            return [ [i.folder,i.role,i.accessLevel] for i in folder_acls ]
        elif mode == 'remove':
            fs.removeFolderACLs(folder_acls,recursive)
            return [ [i.folder,i.role,i.accessLevel] for i in folder_acls ]
        else:
            raise ModeTypeError,mode
        return folder_acls

    def __getFolderACLs(self, Folder):
        fs = self.__ts.folder.FolderService
        folderref = self.getFolderRefs(Folder)
        return fs.getFolderACLs(folderref)

    def listFolderACLs(self,Folder):
        fs = self.__ts.folder.FolderService
        access_list = self.__getFolderACLs(Folder)
        for i in access_list:
            print "Folder: %s" % fs.getFolderPaths( [ i.folder ] )[0].path
            print "AccessLevel: %s" % i.accessLevel
            print "UserGroup: %s" % i.role
            print

    def addFolderACLs(self, Folder, Permission, UserGroup, recursive=False, propagateListAccessUp=True):
        return self.__FolderACLs("add",Folder,Permission,UserGroup,recursive,propagateListAccessUp)

    def removeFolderACLs(self, Folder, Permission, UserGroup, recursive=False):
        return self.__FolderACLs("remove",Folder,Permission,UserGroup,recursive,None)

#   def listFolder(self, Folder, recursive=False, type=''):
#       folder_contents = [] 
#       fs = self.__ts.folder.FolderService
#       folderrefs = self.getFolderRefs(Folder)
#       self.getObjectStringPath(folderrefs,recursive,type)
#       for i in fs.getFolderPaths(folderrefs):
#           print "%s%s" % (os.path.split(i.path)[0],i)
#       folder_contents.append(obj_path)
#       return folder_contents

    def moveToFolder(self,Src,FolderDest):
        fs = self.__ts.folder.FolderService
        folder_dest_list = self.getFolderRefs(FolderDest)
        if len(folder_dest_list) > 1:
            raise MultipleFoldersFound,folder_dest_list
        if type(Src) == str:
            if re.search(',',Src):
                raise TypeError,Src
            if Src.startswith('/'):
                Src = Src[1:]
            object_ref = fs.getFNode(re.split('/',Src))
        else:
            raise TypeError,Src 
        fs.move(object_ref,folder_dest_list[0])
        print "Moved object %s to folder %s" % (object_ref,folder_dest_list[0])

    def getPlatformRefs(self,platform,regex=False):
        #
        # had to come up with a different way to get the platform because of the discrepency between
        # the search name and what is displayed.
        #
        if not platform:
            raise NullSearchValue,"getPlatformRefs"
        if type(platform) == str:
            if re.match('^[ \t]+$',platform):
                raise NullSearchValue,"getPlatformRefs"
        # if regex or isinstance(platform,int) or isinstance(platform,long):
        if isinstance(platform,(int,long)) or not re.search('[Ww]indow',platform) or regex:    
            return self.__filterByName( objectString=platform,
                                        objectService=self.__ts.device.PlatformService,
                                        searchType='platform',
                                        findMethod='findPlatformRefs',
                                        objectRef=PlatformRef,
                                        regex=regex,
                                        nameAttribute='form_name'   )
        else:
            # To make up for bug in finding Windows platform
            platformservice = self.__ts.device.PlatformService
            platformrefs = []
            filter = Filter()
            filter.objectType = 'platform'
            filter.expression = '%s CONTAINS_WITH_WILDCARDS "%s"' % ('platform_name',"*Windows*")
            platformrefs = platformservice.findPlatformRefs(filter)
            platform = re.sub('\*','.*',platform)
            return [ platformref for platformref in platformrefs if re.match("^" + platform + "$",platformref.name) ]            

    def getCustomerRefs(self,customer,regex=False):
        if not customer:
            if not isinstance(customer,(int,long)):
                raise NullSearchValue,"getCustomerRefs"
        if type(customer) == str:
            if re.match('^[ \t]+$',customer):
                raise NullSearchValue,"getCustomerRefs"
        return self.__filterByName( objectString=customer,
                                    objectService=self.__ts.locality.CustomerService,
                                    searchType='customer',
                                    findMethod='findCustomerRefs',
                                    objectRef=CustomerRef,
                                    regex=regex,
                                    nameAttribute='\.name'   )
    

    def getSoftwarePolicyRefs(self,software_policy,regex=False):
        if not software_policy:
            raise NullSearchValue,"getSoftwarePolicyRefs"
        if type(software_policy) == str:
            if re.match('^[ \t]+$',software_policy):
                raise NullSearchValue,"getSoftwarePolicyRefs"
        return self.__filterByFolderPath(   objectString=software_policy,
                                            objectService=self.__ts.swmgmt.SoftwarePolicyService,
                                            searchType='software_policy',
                                            findMethod='findSoftwarePolicyRefs',
                                            objectRef=SoftwarePolicyRef,
                                            regex=regex,
                                            nameAttribute='\.name'  )

    def getOSSequenceRefs(self,osSequence,regex=False):
        if not osSequence:
            raise NullSearchValue,"getOSSequenceRefs"
        if type(osSequence) == str:
            if re.match('^[ \t]+$',osSequence):
                raise NullSearchValue,"getOSSequenceRefs"
        return self.__filterByFolderPath(   objectString=osSequence,
                                            objectService=self.__ts.osprov.OSSequenceService,
                                            searchType='os_sequence',
                                            findMethod='findOSSequenceRefs',
                                            objectRef=OSSequenceRef,
                                            regex=regex,
                                            nameAttribute='\.name'  )

    def getOGFSScriptRefs(self,ogfs_script,regex=False):
        if not ogfs_script:
            raise NullSearchValue,"getOGFSScriptRefs"
        if type(ogfs_script) == str:
            if re.match('^[ \t]+$',ogfs_script):
                raise NullSearchValue,"getOGFSScriptRefs"
        return self.__filterByFolderPath(   objectString=ogfs_script,
                                            objectService=self.__ts.script.OGFSScriptService,
                                            searchType='ogfs_script',
                                            findMethod='findOGFSScriptRefs',
                                            objectRef=OGFSScriptRef,
                                            regex=regex,
                                            nameAttribute='\.name'  )


    def runOGFSScript(self,ogfsscript_id_name,parameters='',email=False,workingDir='/',timeout=10,time_offset=3):
        jobStarted = False
        ogfsService = self.__ts.script.OGFSScriptService
        ogfsscriptRef = self.getOGFSScriptRefs(ogfsscript_id_name)
        if len(ogfsscriptRef) > 1:
            raise MultipleOGFSScriptFound,ogfsscriptRef
        elif len(ogfsscriptRef) == 0:
            raise NoOGFSScriptFound,ogfsscriptRef
        ogfsref = ogfsscriptRef[0]
        ogfsJobArgs = OGFSScriptJobArgs()
        ogfsJobArgs.workingDir = workingDir
        ogfsJobArgs.timeOut = timeout
        ogfsJobArgs.parameters = parameters
        while not jobStarted:
            jobSchedule = JobSchedule()
            jobSchedule.startDate = int(time.time()+ time_offset)
            try:
                if email:
                    jobId = ogfsService.startOGFSScript(    ogfsref,
                                                            ogfsJobArgs,
                                                            self.__username,
                                                            self.__jobNotify,
                                                            jobSchedule).id
                else:
                    jobNotify = JobNotification()
                    jobNotify.onFailureOwner = ''
                    jobNotify.onSuccessOwner = ''
                    jobNotify.onFailureRecipients = [''] 
                    jobNotify.onSuccessRecipients = ['']                    
                    jobStarted = True
                    jobId = ogfsService.startOGFSScript(    ogfsref,
                                                            ogfsJobArgs,
                                                            self.__username,
                                                            jobNotify,
                                                            jobSchedule).id

            except PastScheduledDateException: 
                print "OGFS Script (%s) is being rescheduled" % \
                    ogfsService.getOGFSScriptVO(ogfsref).name 
                jobStarted = False 
                time_offset = time_offset + 1
        return jobId
    
    def getOGFSScriptSource(self,ogfs_script,versionLabel=None):
        os = self.__ts.script.OGFSScriptService
        ogfsrefs = self.getOGFSScriptRefs(ogfs_script)
        if len(ogfsrefs) > 1:
            raise MultipleObjectRefsFound,ogfsrefs
        if len(ogfsrefs) < 1:
            raise NoObjectRefFound,ogfsrefs
        ogfsscriptvo = os.getOGFSScriptVO(ogfsrefs[0])
        if not versionLabel:
            versionLabel = ogfsscriptvo.currentVersion.versionLabel
        return os.getSource(ogfsscriptvo.ref,versionLabel)

    def getServerScriptRefs(self,server_script,regex=False):
        if not server_script:
            raise NullSearchValue,"getServerScriptRefs"
        if type(server_script) == str:
            if re.match('^[ \t]+$',server_script):
                raise NullSearchValue,"getServerScriptRefs"
        return self.__filterByFolderPath(   objectString=server_script,
                                            objectService=self.__ts.script.ServerScriptService,
                                            searchType='server_script',
                                            findMethod='findServerScriptRefs',
                                            objectRef=ServerScriptRef,
                                            regex=regex,
                                            nameAttribute='\.name'  )

    def getServerScriptInfo(self,server_script):
        sss = self.__ts.script.ServerScriptService
        if isinstance(server_script,ServerScriptRef):
            ssref = [ server_script ]
        else:
            ssref = self.getServerScriptRefs(server_script)
        if len(ssref) > 1:
            raise MultipleObjectRefsFound,ssref
        if len(ssref) < 1:
            raise NoObjectRefFound,ssref
        server_script_vo = sss.getServerScriptVO(ssref[0])
        print "%s" % server_script_vo
        serverScriptInfo = {}
        for i in [ k for k in dir(server_script_vo) if not (re.match('__[A-Za-z_-]+__',k) or re.match('[A-Z_]+',k)) ]:
            serverScriptInfo[i] = eval("server_script_vo.%s" % i)
        return serverScriptInfo
    
    def runAdHocScript(self,scriptfile,targetRefs,codeType,scriptArgs=None,timeout=10,email=False,regex=False,timeoffset=3):
        try:
            adhoc = {}
            fd = file(scriptfile,'r+')
            adhoc['scriptSrc'] = string.join(fd.readlines(),'')
            fd.close()
            adhoc['codeType'] = codeType
            return self.runServerScript(None,targetRefs,scriptArgs,adhoc,timeout,email,regex,timeoffset)
        except IOError,args:
            raise IOError,args

    def runServerScript(self,script_id_name,targetRefs,scriptArgs=None,adhoc=None,timeout=10,email=False,regex=False,time_offset=3):
        jobStarted = False
        ssService = self.__ts.script.ServerScriptService
        pService = self.__ts.device.PlatformService
        sService = self.__ts.server.ServerService
        dgService = self.__ts.device.DeviceGroupService
        if adhoc:
            if script_id_name:
                raise InvalidArgs,"Either script_id_name or adhoc need to be set to None"
            else:
                source = adhoc['scriptSrc']
                sourceCodeType = adhoc['codeType']
        else:            
            ServerScriptRefs = self.getServerScriptRefs(script_id_name,regex)
            if len(ServerScriptRefs) > 1:
                raise MultipleServerScriptFound,ServerScriptRefs
            elif len(ServerScriptRefs) == 0:
                raise NoServerScriptFound,ServerScriptRefs
            ssref = ServerScriptRefs[0]

        if not targetRefs:
            raise NoObjectRefFound,"Couldn't find either servers or the device groups."
        #
        # getServerScriptRefs will return a list of ServerScriptRefs so we need to get just the one element in the list
        #
        ssJobArgs = ServerScriptJobArgs()
        ssJobArgs.targets = targetRefs
        ssJobArgs.timeOut = timeout
        ssJobArgs.parameters = scriptArgs
        if self.isHPSA9x():
            UnixPlatformList = pService.findPlatformFamilies()[9].platforms
            WindowsPlatformList = pService.findPlatformFamilies()[11].platforms
        else:
            UnixPlatformList = pService.findPlatformFamilies()[7].platforms
            WindowsPlatformList = pService.findPlatformFamilies()[9].platforms
        #
        # Check to make sure that the script can execute on the target.
        # If it can't remove it from the ssJobArgs.target list.
        #
        if adhoc:
            codeType = sourceCodeType
            if not codeType in [ServerScriptVO.SH_CODE_TYPE,ServerScriptVO.POWERSHELL_CODE_TYPE,ServerScriptVO.BAT_CODE_TYPE,ServerScriptVO.VBS_CODE_TYPE]:
                raise InvalidArgs,sourceCodeType
        else:
            codeType = ssService.getServerScriptVO(ssref).codeType

        if codeType == ServerScriptVO.SH_CODE_TYPE:
            platformList = UnixPlatformList
        else:
            platformList = WindowsPlatformList
        
        if len(ssJobArgs.targets) == 0:
            raise NoTargetsSpecified,server_id_name
        while not jobStarted:
            jobSchedule = JobSchedule()
            jobSchedule.startDate = int(time.time() + time_offset)
            if not email:
                jobNotify = JobNotification()
                jobNotify.onFailureOwner = ''
                jobNotify.onSuccessOwner = ''
                jobNotify.onFailureRecipients = [''] 
                jobNotify.onSuccessRecipients = ['']
            try:
                if adhoc:
                    if email:
                        jobId = ssService.startAdhocServerScript(   source,
                                                                    sourceCodeType,
                                                                    ssJobArgs,
                                                                    self.__username,
                                                                    self.__jobNotify,
                                                                    jobSchedule).id
                    else:
                        jobId = ssService.startAdhocServerScript(   source,
                                                                    sourceCodeType,
                                                                    ssJobArgs,
                                                                    self.__username,
                                                                    jobNotify,
                                                                    jobSchedule).id                        
                else:
                    if email:
                        jobId = ssService.startServerScript(    ssref,
                                                                ssJobArgs,
                                                                self.__username,
                                                                self.__jobNotify,
                                                                jobSchedule).id
                    else:
                        jobId = ssService.startServerScript(    ssref,
                                                                ssJobArgs,
                                                                self.__username,
                                                                jobNotify,
                                                                jobSchedule).id                        
                jobStarted = True
            except PastScheduledDateException:
                if adhoc:
                    print "Retrying Adhoc Script run"
                else:
                    print "Retrying Server Script (%s) run" % \
                                                    ssService.getServerScriptVO(ssref).name 
                jobStarted = False 
                time_offset = time_offset + 5
        return jobId

    def showServerScriptSource(self,script_id_name,label=None):
        ss = self.__ts.script.ServerScriptService
        sref = self.getServerScriptRefs(script_id_name)[0]
        scriptVersionList = ss.getAllScriptVersions(sref)
        for i in scriptVersionList:
            if i.current:
                currentVersion = i
                break
        return ss.getSource(sref,currentVersion.versionLabel)

    def createServerScript(self,scriptFile,codeType,folder,scriptName='',description='',versionLabel='',runAsSuperUser=True,serverChanging=True):
        ss = self.__ts.script.ServerScriptService
        fs = self.__ts.folder.FolderService
        folderref = self.getFolderRefs(folder)
        scriptExists = False
        if len(folderref) > 1:
            raise MultipleObjectRefsFound,folderref
        elif len(folderref) == 0:
            raise NoObjectRefFound,folderref
        try:
            fd = file(scriptFile,'r+')
            source = string.join(fd.readlines())
            if not scriptName:
                path,scriptName = os.path.split(scriptFile)
            if not description:
                description = scriptName
            for fnode in fs.getChildren(folderref[0],'com.opsware.script.ServerScriptRef'):
                if fnode.name == scriptName:
                    scriptExists = True
                    ssref = fnode
            if scriptExists:
                ssvo = ss.getServerScriptVO(ssref)
            else:
                ssvo = ServerScriptVO()
                ssvo.codeType = codeType
                ssvo.name = scriptName
                ssvo.folder = folderref[0]
                ssvo.description = description
                #ssvo.currentVersion.runAsSuperUser = runAsSuperUser
                ssvo = ss.create(ssvo)
            if not versionLabel:
                if scriptExists:
                    versionLabel = str(string.atoi(ssvo.currentVersion.getVersionLabel()) + 1)
                else:
                    versionLabel = '1'
            serverScriptVersion = ServerScriptVersion()
            serverScriptVersion.usage = description
            serverScriptVersion.createdBy = self.__username
            serverScriptVersion.createdDate = int(time.time())
            serverScriptVersion.versionLabel = versionLabel
            serverScriptVersion.runAsSuperUser = runAsSuperUser
            serverScriptVersion.serverChanging = serverChanging
            ss.createScriptVersion(ssvo.ref,serverScriptVersion,source)
            ss.setCurrentVersion(ssvo.ref,versionLabel)
            return ssvo.ref
        except IOError,args:
            raise IOError,args
        except UniqueVersionStringException,args:
            raise VersionStringConflict,versionLabel

    def getUnitRefs(self,unitName,regex=False):
        if not unitName:
            raise NullSearchValue,"getUnitRefs"
        if type(unitName) == str:
            if re.match('^[ \t]+$',unitName):
                raise NullSearchValue,"getUnitRefs"
        return self.__filterByFolderPath(   objectString=unitName,
                                            objectService=self.__ts.search.SearchService,
                                            searchType='software_unit',
                                            findMethod='findObjRefs',
                                            objectRef=unitRefs,
                                            regex=regex,
                                            nameAttribute='\.fileName'  )

    def getUnitInfo(self,unit_id_name):
        us = self.__ts.pkg.UnitService
        if isinstance(unit_id_name,unitRefs):
            uref = [ unit_id_name ]
        else:
            uref = self.getUnitRefs(unit_id_name)
        if len(uref) > 1:
            raise MultipleObjectRefsFound,uref
        if len(uref) < 1:
            raise NoObjectRefFound,uref
        unit_vo = us.getUnitVO(uref[0])
        unitInfo = {}
        for i in [ k for k in dir(unit_vo) if not re.match('__[A-Za-z_-]+__',k) ]:
            unitInfo[i] = eval("unit_vo.%s" % i)
        return unitInfo

    def getUnitTypes(self):
        us = self.__ts.pkg.UnitService
        return us.findUnitTypes()
    
    def createUnit(self,file_string,unitType,platform_string,folder_string,regex=False,replaceUnit=None,SAPkgName=None):
        try:
            if self.__debug:
                print "token: %s" % self.__ts.token
            uis = unitio.StreamUnit(token=self.__ts.token)
            input_stream = unitio.createUnitInputStreamFromFilename(file_string)
            file_name_string = SAPkgName or os.path.basename(file_string)
            if replaceUnit:
                unitref = self.getUnitRefs(replaceUnit)
                platformrefs = self.getPlatformRefs(platform_string,regex)
                if len(unitref) > 1:
                    raise MultipleObjectRefsFound,unitref
                elif len(unitref) == 0:
                    raise NoObjectRefFound,unitref
                if len(platformrefs) == 0:
                    raise NoObjectRefFound,platform_string
                params = unitio.UnitCreationParams(inputStream=input_stream,unitType=unitType,platformRefs=platformrefs,unitRefToReplace=unitref[0])
            else:
                platformrefs = self.getPlatformRefs(platform_string,regex)
                folderref = self.getFolderRefs(folder_string)
                if len(folderref) > 1:
                    raise MultipleObjectRefsFound,folder_id
                elif len(folderref) == 0:
                    raise NoObjectRefFound,folder_string
                if len(platformrefs) == 0:
                    raise NoObjectRefFound,platform_string
                params = unitio.createParams(input_stream, file_name_string, unitType, platformrefs, folderref[0])
            return uis.createUnit(params)
        except PackageRepositoryCommunicationException,args:
            raise SoftwareRepositoryUploadFailed,args.cause
        except DataAccessEngineCommunicationException,args:
            raise SoftwareRepositoryUploadFailed,args.cause

    def replaceUnit(self,file_string,unitType,replaceUnit,platform_string,altPkgName=None):
        return self.createUnit(file_string,unitType,platform_string,None,False,replaceUnit,altPkgName)

    def uploadUnit(self,file_string,unitType,platform_string,folder_string,regex=False,SAPkgName=None):
        return self.createUnit(file_string,unitType,platform_string,folder_string,regex,None,SAPkgName)

    def downloadUnit(self,SAPkgName,filename,regex=False):
        try:
            uis = unitio.StreamUnit(self.__ts.token)
            pkgref = self.getUnitRefs(SAPkgName,regex)
            if len(pkgref) > 1:
                raise MultipleObjectRefsFound,pkgref
            if len(pkgref) == 0:
                raise NoObjectRefFound,pkgref
            uis.downloadFile(pkgref[0],filename)
        except PackageRepositoryCommunicationException,args:
            raise SoftwareRepositoryDownloadFailed,args.cause
        except DataAccessEngineCommunicationException,args:
            raise SoftwareRepositoryDownloadFailed,args.cause

    def removeUnit(self,unitName,regex=False):
        us = self.__ts.pkg.UnitService
        deletedPkgs = []
        unitRefList = self.getUnitRefs(unitName,regex)
        if len(unitRefList) == 0: 
            raise NoObjectRefFound
        for i in unitRefList:
            try:
                us.remove(i)
                deletedPkgs.append(i)
            except NotFoundException,args:
                raise NoObjectRefFound,args
            except AuthorizationException,args:
                raise PermissionDenied,args
        return deletedPkgs

    def getSnapshotTaskRefs(self,snapshots):
        if not snapshots:
            raise NullSearchValue,"getUnitRefs"
        if type(snapshots) == str:
            if re.match('^[ \t]+$',snapshots):
                raise NullSearchValue,"getUnitRefs"
        objRefs = self.__getObjectRefs( snapshots,
                                        self.__ts.compliance.sco.SnapshotTaskService,
                                        "snapshot_task",
                                        "findSnapshotTaskRefs",
                                        ObjRef=SnapshotTaskRef,
                                        name_attribute='\.name' )
        return objRefs

    def removeAllSnapshotResults(self,snapshots):
        if not snapshots:
            raise NullSearchValue,"removeAllSnapshotTaskResults"
        elif re.match('^[ \t]+$',snapshots):
            raise NullSearchValue,"removeAllSnapshotTaskResults"
        ssrService = self.__ts.compliance.sco.SnapshotResultService
        for i in self.findSnapshotTaskResults(snapshot_task_id_name): ssrService.remove(i)  

    def runSnapshotSpecification(self,snapshots):
        if not snapshots:
            raise NullSearchValue,"runSnapshotSpecification"
        elif re.match('^[ \t]+$',snapshots):
            raise NullSearchValue,"runSnapshotSpecification"
        ssts = self.__ts.compliance.sco.SnapshotTaskService
        filter = self.__getSAObjectNameIdFilter('snapshot_task',snapshots)
        ssref_list = ssts.findSnapshotTaskRefs(filter)
        if len(ssref_list) > 1:
            raise MultipleSnapshotTaskFound,ssref_list
        elif len(ssref_list) == 0:
            raise NoSnapshotTaskFound,ssref_list
        self.__runSnapshotSpecification(ssref_list[0].idAsLong)

    def __runSnapshotSpecification(self,snapshot_id):
        jobStarted = False
        time_offset = 3
        while not jobStarted:
            sstref = SnapshotTaskRef(snapshot_id)
            sstService = self.__ts.compliance.sco.SnapshotTaskService
            jobSchedule = JobSchedule()
            jobSchedule.startDate = int(time.time()+ time_offset)
            try:
                jobId = sstService.startSnapshot(sstref,self.__username,self.__jobNotify,jobSchedule).id
                jobStarted = True
            except PastScheduledDateException:
                print "Snapshot Specification run (%s) is being rescheduled" % \
                    sstService.getSnapshotTaskVO(sstref).name 
                jobStarted = False 
                time_offset = time_offset + 1
        return jobId

    def getJobRef(self, job_id):
        js = self.__ts.job.JobService
        return js.findJobRefs(self.__getSAObjectNameIdFilter('job',job_id))

    def getJobInfo(self, job_id):
        js = self.__ts.job.JobService
        jobref = js.findJobRefs(self.__getSAObjectNameIdFilter('job',job_id))
        job_vo = js.getJobInfoVOs(jobref)
        jobInfo = {}
        for i in [ k for k in dir(job_vo[0]) if not (re.match('__[a-z]+__',k) or re.match('[A-Z]+_[A-Z]+',k))]:
            jobInfo[i] = eval("job_vo[0].%s" % i)
        return jobInfo

    def getJobResultsMap(self, job_id):
        sessionFacade = self.__ds.SessionFacade
        return sessionFacade.getSessionResultsMap(job_id)

    def getCommandResultsMap(self, cmd_id):
        sessionFacade = self.__ds.SessionFacade
        return sessionFacade.getSessionCommandResultsMap(cmd_id)

    def getJobResults(self, job_id):
        js = self.__ts.job.JobService
        ss = self.__ts.script.ServerScriptService
        os = self.__ts.script.OGFSScriptService
        try:
            jobRef = self.getJobRef(job_id)[0]
        except IndexError:
            raise NoObjectRefFound,job_id
        try:
            if not js.getProgress(jobRef):
                jobInfo = self.getJobInfo(job_id)
                jobResultsDict = {'type': jobInfo['type'],'hosts':{}}
                if jobInfo['type'] == 'server.script.run':
                    for jobServerInfo in jobInfo['serverInfo']:
                        jobOutput = {}
                        hostname = jobServerInfo.server.name
                        jobOutputRefs = ss.getServerScriptJobOutput(jobRef,jobServerInfo.server)
                        for jobOutputAttribute in [z for z in dir(jobOutputRefs) if not re.match('__[a-z]+__',z)]:
                            jobOutput[jobOutputAttribute] = eval("jobOutputRefs.%s" % jobOutputAttribute)
                        jobResultsDict['hosts'][hostname] = jobOutput
                elif jobInfo['type'] == 'server.os.install':
                    for jobServerInfo in jobInfo['serverInfo']:
                        jobOutput = {}
                        hostname = jobServerInfo.server.name
                        # Should be only one elemResultInfo item for server.os.install
                        # elemResultInfo[0] has the OS Provisioning messages.
                        jobResultsDict['hosts'][hostname] = js.getResult(js.getResult(jobRef).elemResultInfo[0].job)
                elif jobInfo['type'] == 'ogfs.script.run':
                    #jobOutput = {}
                    #cmd_id = self.getJobResultsMap(long(job_id))['0']['cmd_id']
                    #jobOutput = self.getCommandResultsMap(long(cmd_id))
                    hostname = subprocess.Popen("/bin/uname -n", shell=True, stdout=subprocess.PIPE).stdout.readline().strip()
                    #jobResultsDict['hosts'][hostname] = jobOutput
                    jobResultsDict['hosts'][hostname] = js.getResult(jobRef)
                    jobResultsDict['hosts'][hostname].jobOutput = os.getOGFSScriptJobOutput(JobRef(job_id))
                elif jobInfo['type'] == 'program_apx.execute':
                    hostname = subprocess.Popen("/bin/uname -n", shell=True, stdout=subprocess.PIPE).stdout.readline().strip()
                    jobResultsDict['hosts'][hostname] = js.getResult(jobRef)
                elif jobInfo['type'] == 'server.swpolicy.remediate':
                    jobResultsDict['hosts'][job_id] = self.getJobStatus(job_id)
#                elif jobInfo['type'] == 'server.swpolicy.remediate':
#                    pass
#                elif jobInfo['type'] == 'server.audit.create':
#                    pass
                else:
                    raise JobTypeNotImplemented,jobInfo['type']
            else:
                raise JobStillInProgress,job_id
            return jobResultsDict
        except JobIsScheduledException,args:
            raise JobStillInProgress,job_id
        
    def getJobStatus(self,jobId):
        js = self.__ts.job.JobService
        try:
            jobRef = self.getJobRef(jobId)[0]
        except IndexError:
            raise NoObjectRefFound,jobId
        statusId = js.getJobInfoVO(jobRef).status
        if JobInfoVO.STATUS_ABORTED == statusId:
            status = "ABORTED"
        elif JobInfoVO.STATUS_ACTIVE == statusId:
            status = "ACTIVE"
        elif JobInfoVO.STATUS_BLOCKED == statusId:
            status = "BLOCKED"
        elif JobInfoVO.STATUS_CANCELLED == statusId:
            status = "CANCELLED"
        elif JobInfoVO.STATUS_DELETED == statusId:
            status = "DELETED"
        elif JobInfoVO.STATUS_EXPIRED == statusId:
            status = "EXPIRED"
        elif JobInfoVO.STATUS_FAILURE == statusId:
            status = "FAILURE"
        elif JobInfoVO.STATUS_PENDING == statusId:
            status = "PENDING"
        elif JobInfoVO.STATUS_RECURRING == statusId:
            status = "RECURRING"
        elif JobInfoVO.STATUS_STALE == statusId:
            status = "STALE"
        elif JobInfoVO.STATUS_SUCCESS == statusId:
            status = "SUCCESS"
        elif JobInfoVO.STATUS_TAMPERED == statusId:
            status = "TAMPERED"
        elif JobInfoVO.STATUS_UNKNOWN == statusId:
            status = "UNKNOWN"
        elif JobInfoVO.STATUS_WARNING == statusId:
            status = "WARNING"
        elif JobInfoVO.STATUS_ZOMBIE == statusId:
            status = "ZOMBIE"
        return status


    def getServerHistorybySecs(self,serverref,secs,order='asc'):
        ss = self.__ts.server.ServerService
        #
        # This actually seems to be broken so we need to get all of the history from the server
        # the beginDate and endDate given doesn't seem to correspond to the parameters specified
        # in the twist documentation. This seemed to be the only way get all of the server history.
        #
        beginDate = 0 
        endDate = 5000000000 
        sHistory = ss.getLogEntries(serverref,beginDate,endDate,True)
        secs = long(time.time()) - secs
        bIndex = bisect.bisect([ sHistory[i].date for i in range(0,len(sHistory)) ],secs)
        if order == 'asc':
            hlist = [ { 'user':sHistory[i].user,
                    'summary':sHistory[i].summary,
                    'date':time.strftime("%a %b %d %H:%M:%S %Z %Y",time.localtime(sHistory[i].date))    }
                    for i in range(bIndex,len(sHistory)) ]
            hlist.reverse()
            return hlist
        else:
            return [ {  'user':sHistory[i].user,
                    'summary':sHistory[i].summary,
                    'date':time.strftime("%a %b %d %H:%M:%S %Z %Y",time.localtime(sHistory[i].date))    }
                    for i in range(bIndex,len(sHistory)) ]

    def getServerHistorybyDays(self,serverref,days,order='asc'):
        return self.getServerHistorybySecs(serverref,long(days * 86400),order)

    def getServerHistorybyWeeks(self,serverref,weeks,order='asc'):
        return self.getServerHistorybySecs(serverref,long(weeks * 86400 * 7),order)

    def assignCustomerToServer(self,server,customer,regex):
        customerref = self.getCustomerRefs(customer,regex)
        if len(customerref) > 1:
            raise MultipleObjectRefsFound,"Multiple customers found, need to specify only one."
        if len(customerref) < 1:
            raise NoObjectRefFound,"No customer found. Specify a valid customer."
        serverrefs = self.getServerRefs(server,regex)
        if len(serverrefs) < 1:
            raise NoObjectRefFound,"No servers found. Specify a valid server(s)."
        ss = self.__ts.server.ServerService
        assignedServerCustomer = []
        for serverref in serverrefs:
            ss.setCustomer(serverref,customerref[0])
            assignedServerCustomer.append( (serverref,ss.getServerVO(serverref).customer) )
        return assignedServerCustomer

    def assignCustomerToServerByServerRefs(self,serverRefs,customer,regex):
        customerref = self.getCustomerRefs(customer,regex)
        if len(customerref) > 1:
            raise MultipleObjectRefsFound,"Multiple customers found, need to specify only one."
        if len(customerref) < 1:
            raise NoObjectRefFound,"No customer found. Specify a valid customer."
        if len(serverRefs) < 1:
            raise NoObjectRefFound,"No servers found. Specify a valid server(s)."
        ss = self.__ts.server.ServerService
        for serverref in serverRefs:
            ss.setCustomer(serverref,customerref[0])
            yield (serverref,ss.getServerVO(serverref).customer)

    def getAPXRefs(self,apx_name,name_attribute='\.uniqueName'):
        if not apx_name:
            raise NullSearchValue,"getAPXRefs"
        if type(apx_name) == str:
            if re.match('^[ \t]+$',apx_name):
                raise NullSearchValue,"getAPXRefs"
        objRefs = self.__getObjectRefsbyPath(   self.__ts.folder.FolderService,
                                                self.__ts.search.SearchService,
                                                "getFNode",
                                                "findObjRefs",
                                                "apx",
                                                APXRef,
                                                apx_name,
                                                name_attribute  )
        return objRefs

    def startProgramAPX(self, apx_name, arguments, notification=True, ticketid=None):
        progapxsvc = self.__ts.apx.ProgramAPXService
        apxrefs = self.getAPXRefs(apx_name)
        progapx = apxrefs[0]
        args = ProgramAPXJobArgs()
        args.parameters = arguments
        #args.jobdescription = "test desc"
        args.timeOut = 900 # 15 minutes should be enough
        if notification:
            jobref = progapxsvc.startProgramAPX(progapx, args, ticketid, self.__jobNotify, None)
        else:
            jobref = progapxsvc.startProgramAPX(progapx, args, ticketid, None, None)
        return jobref.id

    def createUserGroup(self,groupName):
        OccGroupFilter = twistserver._findVOs('com.opsware.fido.list.filter.impl','OccGroupFilter')
        filter = OccGroupFilter()
        filter.occGroupName = groupName
        OccGroupList = self.__fs.OccAdminFacade.getOccGroupVOList(filter)
        if (not OccGroupList):
            occGroupVo = self.__fs.OccAdminFacade.createOccGroup(groupName)
        else:
            if (len(OccGroupList) == 1):
                # grpId = OccGroupList[0].occGroupId
                raise ObjectAlreadyExists,OccGroupList[0].groupName
            else:
                raise MultipleUserGroupFound,OccGroupList
        return self.getUserRoleVO(groupName)

    def getUserRoleVO(self,groupName):
        try:
            namespace = "ACCESS_CONTROL"
            rolespace = "OPSWARE"
            roleType = "USER_GROUP"
            userRoleVO = self.__fs.RoleFacade.getRoleVO(namespace,rolespace,roleType,groupName)
        except:
            print " Error while retrieving UserRoleVO for <" + groupName + ">. \n"
            userRoleID = -1
        return userRoleVO

    def __list_contains(self, list, value ):
        try:
            idx = list.index( value )
        except ValueError, reason:
            idx = -1
        return idx

    def resourcePermissionsSync(self, SrcGroupName, DstGroupName):
        SrcGroupId = self.__fs.OccAdminFacade.getOccGroupVOByName(SrcGroupName).occGroupId
        DstGroupId = self.__fs.OccAdminFacade.getOccGroupVOByName(DstGroupName).occGroupId
        OccGroupResourceSettingArg = twistserver._findVOs('com.opsware.fido.args','OccGroupResourceSettingArg')
        resourceType = ["CUSTOMER","FACILITY","DEVICE_GROUP","STACK_LOCKING","STACK"]
        for type in resourceType:
            occGrpResourceSettingArgsList = []
            occGroupResourceSettingVOs = self.__fs.OccAdminFacade.getOccGroupResourceSettingVOsByType(SrcGroupId, type)
            if (occGroupResourceSettingVOs):
                for occGroupResourceSettingVO in occGroupResourceSettingVOs:
                    if (occGroupResourceSettingVO.value != 0):
                        occGrpResourceSettingArgs  = OccGroupResourceSettingArg()
                        occGrpResourceSettingArgs.occResourceType = occGroupResourceSettingVO.occResourceType
                        occGrpResourceSettingArgs.accessLevel = occGroupResourceSettingVO.occAccessLevel
                        occGrpResourceSettingArgs.occResourceId = occGroupResourceSettingVO.value
                        occGrpResourceSettingArgsList.append(occGrpResourceSettingArgs)
            self.__fs.OccAdminFacade.setOccGroupResourceSettingsByType(DstGroupId,type,occGrpResourceSettingArgsList)

    def featurePermissionsSync(self,SrcGroupName,DstGroupName):
        SrcGroupId = self.__fs.OccAdminFacade.getOccGroupVOByName(SrcGroupName).occGroupId
        DstGroupId = self.__fs.OccAdminFacade.getOccGroupVOByName(DstGroupName).occGroupId
        tmplFeatureVOList = self.__fs.OccAdminFacade.getOccFeatureVOsByGroup(SrcGroupId)
        grpFeatureVOList = self.__fs.OccAdminFacade.getOccFeatureVOsByGroup(DstGroupId)
        tmplFeatureIdsList = []
        grpFeatureIdsList = []
        for occFeatureVO in tmplFeatureVOList:
            if (string.find(occFeatureVO.resourceKey,"Folder") == -1):
                tmplFeatureIdsList.append(occFeatureVO.occFeatureId)
        for occFeatureVO in grpFeatureVOList:
            if (string.find(occFeatureVO.resourceKey,"Folder") == -1):
                grpFeatureIdsList.append(occFeatureVO.occFeatureId)

        # try:
        featuresToDelete = []
        for grpFID in grpFeatureIdsList:
            idx = self.__list_contains( tmplFeatureIdsList, grpFID )
            if idx < 0:
                # is in the group but not in the template so remove it
                featuresToDelete.append( grpFID )
            else:
                #already in the group so no need to re-add 
                tmplFeatureIdsList.remove( grpFID )
        self.__fs.OccAdminFacade.addFeatures(DstGroupId,tmplFeatureIdsList)
        self.__fs.OccAdminFacade.removeFeatures(DstGroupId,featuresToDelete)
    #   except:
    #           print "%s" % 
    #       print " Failed to sync Feature permissions for " + DstGroupId

    def __permission_list_contains( self, permList, opList, perm, op ):
        for i in range( len(permList) ):
            if( opList[i].operationName == op.operationName ):
                if permList[i].deviceFieldName and permList[i].deviceFieldName == perm.deviceFieldName:
                    if( permList[i].fieldIds and permList[i].fieldIds == perm.fieldIds):
                        if( permList[i].logins and permList[i].logins == perm.logins ):
                            return i
                        else:
                            if( perm.logins ):
                                return -1
                            else:
                                return i
                    else:
                        if( perm.fieldIds ):
                            return -1
                        else:
                            return i
                else:
                    if( perm.deviceFieldName ):
                        return -1
                    else:
                        return i
        return -1

    # globalShellPermissionsSync - Compares the OGSH permissions associated with the occGroup created from
    # AD and the appropriate permissions template.  It adds any permissions found only in the template and 
    # removes any permissoins found only in the group.
    def globalShellPermissionsSync(self, SrcGroupName, DstGroupName):
#       try:
        BOTH = ["device","login_names"]
        DEV = ["device"]
        LOGIN = ["login_names"]
        NONE = []

        tmplRoleID = self.getUserRoleRefs(SrcGroupName)[0].idAsLong
        groupRoleID = self.getUserRoleRefs(DstGroupName)[0].idAsLong

        # Get a list of operations for the <TEMPLATE_PERMISSION> group
        tmplOperationsVOList = self.__fs.ShellAdminFacade.getShellOperations(tmplRoleID)

        # Get a list of operations for the OCC Group
        groupOperationsVOList = self.__fs.ShellAdminFacade.getShellOperations(groupRoleID)
        # Create an Operation Object
        paramSwitch = { "launchGlobalShell": NONE,
                        "loginToServer": BOTH,
                        "readServerComplus": BOTH,
                        "readServerFilesystem": BOTH,
                        "readServerMetabase": BOTH,
                        "readServerRegistry": BOTH,
                        "relayRdpToServer": DEV,
                        "runTrustedOnServer": BOTH,
                        "runCommandOnServer": BOTH,
                        "writeServerFilesystem": BOTH }

        tmplPerms = []
        tmplOps = []
        grpPerms = []
        grpOps = []

        for opVO in tmplOperationsVOList:
            op = Operation()
            op.operationName = opVO.operationName
            op.operationParameters = paramSwitch[op.operationName]
            # Get ist of permVOs which have the permissions details for each operation.
            permsVOList = self.__fs.ShellAdminFacade.getShellPermSelections( tmplRoleID, op )
            # print permsVOList
            for perm in permsVOList:
                tmplPerms.append( perm )
                tmplOps.append( op )

        for opVO in groupOperationsVOList:
            op = Operation()
            op.operationName = opVO.operationName
            op.operationParameters = paramSwitch[op.operationName]
            permsVOList1 = self.__fs.ShellAdminFacade.getShellPermSelections( groupRoleID, op )
            # print permsVOList
            for perm in permsVOList1:
                grpPerms.append( perm )
                grpOps.append( op )

        permsToRevoke = []
        opsToRevoke = []

        for i in range( len(grpPerms) ):
            idx = self.__permission_list_contains( tmplPerms, tmplOps, grpPerms[i], grpOps[i] )
            if idx < 0:
                permsToRevoke.append( grpPerms[i] )
                opsToRevoke.append( grpOps[i] )
            else:
                tmplPerms.remove( tmplPerms[idx] )
                tmplOps.remove( tmplOps[idx] )

        for j in range( len( tmplPerms ) ):
            perm = tmplPerms[j]
            if( perm.deviceFieldName ):
                opParams = paramSwitch[tmplOps[j].operationName]
                if opParams == BOTH:
                    fieldList = perm.fieldIds
                    loginList = perm.logins
                elif opParams == DEV:
                    fieldList = perm.fieldIds
                    loginList = [""]
                else:
                    fieldList =[""]
                    loginList = perm.logins

                for fieldID in fieldList:
                    for login in loginList:
                        if( perm.deviceFieldName == "device_facility_id" ):
                            self.__fs.ShellAdminFacade.addPermissionForFacility( groupRoleID, tmplOps[j], fieldID, login )
                        elif( perm.deviceFieldName == "device_group_id" ):
                            self.__fs.ShellAdminFacade.addPermissionForGroup( groupRoleID, tmplOps[j], fieldID, login )
                        else:
                            self.__fs.ShellAdminFacade.addPermissionForCustomer( groupRoleID, tmplOps[j], fieldID, login )
            else:
                self.__fs.ShellAdminFacade.addPermission( groupRoleID, tmplOps[j] )

        for j in range( len( permsToRevoke ) ):
            # these are the permissions that need to be revoked
            perm = permsToRevoke[j]
            if( perm.deviceFieldName ):
                if( perm.fieldIds ):
                    fieldIdList = perm.fieldIds
                else:
                    fieldIdList = [""]
                for i in range( len( perm.fieldIds ) ):
                    if( perm.deviceFieldName == "device_facility_id" ):
                        self.__fs.ShellAdminFacade.revokePermissionForFacility( groupRoleID, opsToRevoke[j], fieldIdList[i] )
                    else:
                        if( perm.deviceFieldName == "device_group_id" ):
                            self.__fs.ShellAdminFacade.revokePermissionForGroup( groupRoleID, opsToRevoke[j], fieldIdList[i] )
                        else:
                            self.__fs.ShellAdminFacade.revokePermissionForCustomer( groupRoleID, opsToRevoke[j], fieldIdList[i] )
            else:
                self.__fs.ShellAdminFacade.revokePermission( groupRoleID, opsToRevoke[j] )
#   except:
#           print " Failed to sync Global Shell permissions for " + SrcGroupName

    def cloneUserGroup(self,SrcGroupName,CloneGroupName):
        grpId = self.createUserGroup(CloneGroupName)
        self.resourcePermissionsSync(SrcGroupName,CloneGroupName)
        self.featurePermissionsSync(SrcGroupName,CloneGroupName)
        self.globalShellPermissionsSync(SrcGroupName,CloneGroupName)
        uRef = self.getUserRoleRefs(CloneGroupName)[0]
        userrole_vo = self.__ts.fido.UserRoleService.getUserRoleVO(uRef)
        UserRoleInfo = {}
        for i in [ k for k in dir(userrole_vo) if not re.match('__[A-Za-z_-]+__',k) ]:
            UserRoleInfo[i] = eval("userrole_vo.%s" % i)
        return UserRoleInfo

    def getUserListfromUserGroup(self, GroupName):
    #   try:
        GroupId = self.__fs.OccAdminFacade.getOccGroupVOByName(GroupName).occGroupId
        userList = self.__fs.OccAdminFacade.getUserVOsByGroup(GroupId)
        userlist = []
        for i in userList:
            userlist.append(i.username)
        userlist.sort()
    # except TwistException,args:
    #   raise PytwistCallException
        return userlist

    def getUserGroupfromUser(self, username):
        OccGroupUserFilter = twistserver._findVOs('com.opsware.fido.list.filter.impl','OccGroupUserFilter')
        Filter = OccGroupUserFilter()
        userList = self.__fs.OccAdminFacade.getUserVOList(Filter)
        userId = None
        for i in userList:
            if i.username == username and i.userStatus == 'ACTIVE' and i.accountStatus == 'ACTIVE':
                userId = i.userId
                break
        if not userId:
            raise NoObjectRefFound,username
        userGroup = self.__fs.OccAdminFacade.getOccGroupVOsByUser(userId)
        usergroup = []
        for j in userGroup:
            usergroup.append(j.groupName)
        usergroup.sort()
        return usergroup

    def UnlockSoftwarePolicy(spname):
        spService = self.__ts.swmgmt.SoftwarePolicyService
        spRef = self.getSoftwarePolicyRefs(spname)
        if len(spRef) > 1:
            raise MultipleObjectRefsFound,spRef
        elif len(spRef) == 0:
            raise NoObjectRefFound,spRef
        spVO = spService.getSoftwarePolicyVOs(spname)
        spVO.locked = False
        return spService.update(spRef,spVO,False,True)

    def getCustomAttribute(self,ObjectRef,key,scope=True):
        try:
            twistHandle = self.__ts
            objRefRepr = re.sub("(.*\()([A-Za-z]+\:[0-9]*[^)])(\\).*)","\\2","%s" % ObjectRef)
            if self.__debug:
                print "objRefRepr: %s" % objRefRepr
            (objRefString,objId) = re.split(":",objRefRepr)
            objService = re.sub("Ref","Service",objRefString)
            (objRootModulePath,objModule) = os.path.splitext(ObjectRef.__module__)
            objService = objModule + "." + objService
            return eval("twistHandle%s.%s" % (objService,"getCustAttr"))(ObjectRef,key,scope)
        except NoSuchFieldException:
            raise NoCustomAttributeFound


    def listCustomAttributes(self):
        pass

    def setCustomAttribute(self, ObjectRef, key, value):
        try:
            twistHandle = self.__ts
            objRefRepr = re.sub("(.*\()([A-Za-z]+\:[0-9]*[^)])(\\).*)","\\2","%s" % ObjectRef)
            if self.__debug:
                print "objRefRepr: %s" % objRefRepr
            (objRefString,objId) = re.split(":",objRefRepr)
            objService = re.sub("Ref","Service",objRefString)
            (objRootModulePath,objModule) = os.path.splitext(ObjectRef.__module__)
            objService = objModule + "." + objService
            return eval("twistHandle%s.%s" % (objService,"setCustAttr"))(ObjectRef,key, value)
        except NotFoundException:
            raise NoObjectRefFound

    def createCustomField(self,customFieldName):
        ss = self.__ts.server.ServerService
        vs = self.__ts.custattr.VirtualColumnService
        vcVO = VirtualColumnVO()
        vcVO.name = customFieldName
        vcVO.type = 'SHORT_STRING'
        vcVO.displayName = customFieldName
        newVCVO = vs.create(vcVO)
        ss.attachVirtualColumn(newVCVO.ref)

    def deleteCustomField(self,customFieldName):
        vs = self.__ts.custattr.VirtualColumnService
        ss = self.__ts.server.ServerService
        vcref = vs.findVirtualColumnRef(customFieldName)
        ss.detachVirtualColumn(vcref)
        vs.remove(vcref)

    def setServerCustomFields(self,serverName,customFieldPattern,value,regex=False):
        ss = self.__ts.server.ServerService
        sRefs = self.getServerRefs(serverName,regex)
        resultDict = {}
        if len(sRefs) == 0:
            raise NoObjectRefFound,sRef
        for sRef in sRefs:
            customFields = self.getServerCustomFields(sRef,customFieldPattern,regex)
            customFieldDict = {}
            if len(customFields[sRef]) == 0:
                raise NoCustomFieldFound,customFieldPattern
                continue
            for customfielddict in customFields[sRef]:
                customFieldName = customfielddict.iterkeys().next()
                oldvalue = ss.getCustomField(sRef,customFieldName)
                ss.setCustomField(sRef,customFieldName,value)
                customFieldDict[customFieldName] = {'oldvalue':oldvalue,'newvalue':value}
            resultDict[sRef] = customFieldDict
        return resultDict

    def setServerCustomFieldsByServerRefs(self,serverRefs,customFieldPattern,value,regex=False):
        ss = self.__ts.server.ServerService
        resultDict = {}
        if len(serverRefs) == 0:
            raise NoObjectRefFound,"server(s)"
        for sRef in serverRefs:
            customFields = self.getServerCustomFieldsByServerRefs([sRef],customFieldPattern,regex)
            customFieldDict = {}
            if len(customFields[sRef]) == 0:
                raise NoCustomFieldFound,customFieldPattern
                continue
            for customfielddict in customFields[sRef]:
                customFieldName = customfielddict.iterkeys().next()
                oldvalue = ss.getCustomField(sRef,customFieldName)
                ss.setCustomField(sRef,customFieldName,value)
                customFieldDict[customFieldName] = {'oldvalue':oldvalue,'newvalue':value}
            resultDict[sRef] = customFieldDict
        return resultDict
    
    def setServerAttributeByServerRefs(self,server_refs,attribute_name,attribute_value,regex=False):
        ss = self.__ts.server.ServerService
        if not isinstance(server_refs, list):
            raise TypeError, server_refs
        if len(server_refs) == 0:
            raise NoObjectRefFound, server_refs
        server_vos = ss.getServerVOs(server_refs)
        #
        # check if attribute exist for the first one because if it exists
        # it exists for all the server_vos
        #
        if attribute_name in dir(server_vos[0]):
            for server_vo in server_vos:
                server_vo.__setattr__(attribute_name, attribute_value)
                yield ss.update(server_vo.ref, server_vo, True, True)
        else:
            raise AttributeError, attribute_name

    def getServerCustomFields(self,serverName,customFieldPattern,regex=False,):
        ss = self.__ts.server.ServerService
        serverCustomFields = {}
        if not customFieldPattern or customFieldPattern == '':
            customFieldPattern = "*"
        sRefs = self.getServerRefs(serverName,regex)
        if len(sRefs) == 0:
            raise NoObjectRefFound,sRefs
        for sref in sRefs:
            customFieldDict = ss.getCustomFields(sref)
            keys = customFieldDict.keys()
            if regex:
                filteredKeys = self.__filteredListWithRegEx(customFieldPattern,keys,attribute='__str__()')
            else:
                filteredKeys = self.__filteredListWithWildCards(customFieldPattern,keys,attribute='__str__()')
            customFields = []
            for i in filteredKeys:
                value = customFieldDict[i]
                if not value:
                    value = ''
                customFields.append({i:value})
            serverCustomFields[sref] = customFields
        return serverCustomFields

    def getServerCustomFieldsByServerRefs(self,serverRefs,customFieldPattern,regex=False):
        ss = self.__ts.server.ServerService
        serverCustomFields = {}
        if not customFieldPattern or customFieldPattern == '':
            customFieldPattern = "*"
        if len(serverRefs) == 0:
            raise NoObjectRefFound,sRefs
        for sref in serverRefs:
            customFieldDict = ss.getCustomFields(sref)
            keys = customFieldDict.keys()
            if regex:
                filteredKeys = self.__filteredListWithRegEx(customFieldPattern,keys,attribute='__str__()')
            else:
                filteredKeys = self.__filteredListWithWildCards(customFieldPattern,keys,attribute='__str__()')
            customFields = []
            for i in filteredKeys:
                value = customFieldDict[i]
                if not value:
                    value = ''
                customFields.append({i:value})
            serverCustomFields[sref] = customFields
        return serverCustomFields

    def getSearchableTypes(self):
        searchService = self.__ts.search.SearchService
        return searchService.getSearchableTypes()

    def getSearchableAttributes(self,searchType):
        try:
            searchService = self.__ts.search.SearchService
            searchAttributes = searchService.getSearchableAttributes(searchType)
            if searchType == 'device':
                ss = self.__ts.server.ServerService
                searchAttributes = searchAttributes + ss.getVirtualColumns()
        except InvalidSearchTypeException:
            raise UnknownSearchType,searchType
        return searchAttributes

    def getSearchableAttributeOperators(self,searchType,searchAttribute):
        try:
            searchService = self.__ts.search.SearchService
            attributeOperators = searchService.getSearchableAttributeOperators(searchType,searchAttribute)
        except InvalidSearchTypeException:
            raise UnknownSearchType,searchType
        except SearchException:
            raise UnknownSearchAttribute,searchAttribute
        return attributeOperators

    def getFilterSQL(self,objectType,expression):
        try:
            searchService = self.__ts.search.SearchService
            filter = Filter()
            filter.expression = expression
            filter.objectType = objectType
            sqlstring = searchService.getFilterSQL(filter)
        except InvalidSearchGrammarException,args: 
            print "InvalidSearchGrammerException"
            raise InvalidSearchExpression,args.message
        except SearchException,args:
            print "SearchException"
            raise InvalidSearchExpression,args.message
        except InvalidSearchTypeException,args:
            print "InvalidSearchTypeException"
            raise InvalidSearchExpression,args
        return sqlstring

    def findObjRefs(self,searchType,expression):
        try:
            searchService = self.__ts.search.SearchService
            filter = Filter()
            filter.expression = expression
            filter.objectType = searchType
            objList = searchService.findObjRefs(filter)
        except InvalidSearchGrammarException,args: 
            print "InvalidSearchGrammerException"
            raise InvalidSearchExpression,args.message
        except SearchException,args:
            print "SearchException"
            raise InvalidSearchExpression,args.message
        except InvalidSearchTypeException,args:
            print "InvalidSearchTypeException"
            raise InvalidSearchExpression,args
        return objList

    def getConfigurationRefs(self,configurationName,regex=False):
        if not configurationName:
            raise NullSearchValue,"getConfigurationRefs"
        if type(ConfigurationRef) == str:
            if re.match('^[ \t]+$',configurationName):
                raise NullSearchValue,"configurationName"
        return self.__filterByFolderPath(   objectString=configurationName,
                                            objectService=self.__ts.acm.ConfigurationService,
                                            searchType='configuration',
                                            findMethod='findConfigurationRefs',
                                            objectRef=ConfigurationRef,
                                            regex=regex,
                                            nameAttribute='\.name'  )

    def findConfigurationParameter(self, configurableRefs, parameter, itemIndex, regex, match=True):
        # configurableRefs - List of either ServerRefs, DeviceGroupRefs, and ConfigurationRefs
        # parameter - search value to find
        # itemIndex - 0 for a name search, 1 for a value search, and 2 for all
        # regex - to use regular expressions for the parameter search or not
        if self.__debug:
            print "%s" % configurableRefs
        
        def findParameter(valueset):
            foundValuesetKeys = []
            if valueset:
                for item in valueset.iteritems():
                    if itemIndex == 2:
                        foundValuesetKeys.append(item[0])
                    else:
                        if regex:
                            if self.__debug:
                                print "parameter: %s" % parameter
                                print "regex: %s" % regex
                                print "item: %s" % item[itemIndex]
                            if match:                                
                                if re.match(parameter,item[itemIndex]):
                                    foundValuesetKeys.append(item[0])
                            else:
                                if re.search(parameter,item[itemIndex]):
                                    foundValuesetKeys.append(item[0])
                                
                        else:
                            if parameter == item[itemIndex]:
                                foundValuesetKeys.append(item[0])
            return foundValuesetKeys
        
        def findValueSet(configurableVO):
            configObject = None
            if configurableVO.valueset:
                coKeys = findParameter(configurableVO.valueset)
                if coKeys:
                    configObject = ConfigurableObject(configurableVO,coKeys)
            if configurableVO.instances:
                for index in range(0,len(configurableVO.instances)):
                    instKeys = findParameter(configurableVO.instances[index].valueset)
                    if instKeys:
                        if not configObject:
                            configObject = ConfigurableObject(configurableVO,[])
                        configObject.instances.append(ApplicationInstanceObject(index,instKeys))
            if configObject:
                if itemIndex == 0:
                    configObject.searchKey = parameter
                if itemIndex == 1:
                    configObject.searchValue = parameter
            return configObject

        class ApplicationInstanceObject:
            def __init__(self,index,foundValuesetKeys):
                self.index = index
                self.foundValuesetKeys = foundValuesetKeys

        class ConfigurableObject:
            def __init__(self,configVO,foundValuesetKeys):
                self.configVO = configVO
                self.foundValuesetKeys = foundValuesetKeys
                self.instances = []
                self.searchKey = None
                self.searchValue = None

        serverService = self.__ts.server.ServerService    
        configService = self.__ts.acm.ConfigurationService
        deviceGroupService = self.__ts.device.DeviceGroupService
        customerService = self.__ts.locality.CustomerService
        facilityService = self.__ts.locality.FacilityService
        #configurableObjects = []
        idIndexList = []

        for configurableRef in configurableRefs:
            if isinstance(configurableRef,(ConfigurationRef,CustomerRef,FacilityRef)):
                if isinstance(configurableRef,ConfigurationRef):
                    configurableVO = configService.getConfigurableVO(configurableRef)
                elif isinstance(configurableRef,FacilityRef):
                    configurableVO = facilityService.getConfigurableVO(configurableRef)
                else:
                    configurableVO = customerService.getConfigurableVO(configurableRef)
                if not configurableVO.ref in idIndexList:
                    configObj = findValueSet(configurableVO)
                    if configObj:
                        idIndexList.append(configObj.configVO.ref)
                        #configurableObjects.append(configObj)
                        yield configObj
            elif isinstance(configurableRef,(ServerRef,DeviceGroupRef)):
                if isinstance(configurableRef,ServerRef):
                    configurableVOs = serverService.getScopedConfigurableVOs(configurableRef,ConfigurationRef(0),'')
                else:
                    configurableVOs = deviceGroupService.getScopedConfigurableVOs(configurableRef,ConfigurationRef(0),'')
                for configurableVO in configurableVOs:
                    if not configurableVO.ref in idIndexList:
                        configObj = findValueSet(configurableVO)
                        if configObj:
                            idIndexList.append(configObj.configVO.ref)
                            #configurableObjects.append(configObj)
                            yield configObj
            else:
                raise IncorrectObjectRef,"Configurable type not accepted."
        #return configurableObjects

    def __dictConfigKeys(self,configurationRefs,parameter,itemIndex,regex):
        dictConfigKeys = {}
        for configObject in self.findConfigurationParameter(configurationRefs, parameter, itemIndex, regex):
            if configObject.configVO.valueset or isinstance(configObject.configVO.ref,(ServerRef,DeviceGroupRef)):
                listNameValue = []
                for foundValuesetKey in configObject.foundValuesetKeys:
                    listNameValue.append((foundValuesetKey,configObject.configVO.valueset[foundValuesetKey]))
                dictConfigKeys[configObject.configVO.ref] = listNameValue
            for appInstance in configObject.instances:
                listNameValue = []
                appInstanceVO = configObject.configVO.instances[appInstance.index]
                for foundValuesetKey in appInstance.foundValuesetKeys:
                    listNameValue.append((foundValuesetKey,appInstanceVO.valueset[foundValuesetKey]))
                dictConfigKeys[appInstanceVO.ref] = listNameValue
        return dictConfigKeys
    

    def listValueSet(self,configurationName,regex=False):
        dictConfigKeys = {}
        configurationRefs = self.getConfigurationRefs(configurationName,regex=False)
        return self.__dictConfigKeys(configurationRefs,None,2,regex)

    def listValueSetByServer(self,serverName,regex=False):
        serverRefs = self.getServerRefs(serverName,regex)
        return self.__dictConfigKeys(serverRefs, None, 2, regex)

    def listValueSetByCustomer(self,customer,regex=False):
        serverRefs = self.getServerRefsByCustomer(customer,regex)
        return self.__dictConfigKeys(serverRefs, None, 2, regex)

    def listValueSetByFacility(self,facility,regex=False):
        serverRefs = self.getServerRefsByFacility(facility,regex)
        return self.__dictConfigKeys(serverRefs, None, 2, regex)

    def findConfigurationName(self,configurationName,name,regex=False):
        configurationRefs = self.getConfigurationRefs(configurationName,regex)
        return self.__dictConfigKeys(configurationRefs, parameter=name, itemIndex=0, regex=regex)

    def findConfigurationNameByServer(self,serverName,name,regex=False):
        serverRefs = self.getServerRefs(serverName,regex)
        return self.__dictConfigKeys(serverRefs, parameter=name, itemIndex=0, regex=regex)
    
    def findConfigurationNameByCustomer(self,customer,name,regex=False):
        serverRefs = self.getServerRefsByCustomer(customer,regex)
        return self.__dictConfigKeys(serverRefs, parameter=name, itemIndex=0, regex=regex)
    
    def findConfigurationNameByFacility(self,facility,name,regex=False):
        serverRefs = self.getServerRefsByFacility(facility,regex)
        return self.__dictConfigKeys(serverRefs, parameter=name, itemIndex=0, regex=regex)

    def findConfigurationValue(self,configurationName,value,regex=False):
        configurationRefs = self.getConfigurationRefs(configurationName,regex)
        return self.__dictConfigKeys(configurationRefs, parameter=value, itemIndex=1, regex=regex)

    def findConfigurationValueByServer(self,serverName,value,regex=False):
        serverRefs = self.getServerRefs(serverName,regex)
        return self.__dictConfigKeys(serverRefs, parameter=value, itemIndex=1, regex=regex)

    def findConfigurationValueByCustomer(self,customer,value,regex=False):
        serverRefs = self.getServerRefsByCustomer(customer,regex)
        return self.__dictConfigKeys(serverRefs, parameter=value, itemIndex=1, regex=regex)

    def findConfigurationValueByFacility(self,facility,value,regex=False):
        serverRefs = self.getServerRefsByFacility(facility,regex)
        return self.__dictConfigKeys(serverRefs, parameter=value, itemIndex=1, regex=regex)

#    def replaceConfigurationValue(self,configurationName,name,value,regex=False,local=False,backupDirectory=None):
#        configRefs = self.getConfigurationRefs(configurationName,regex)
#        configObjs = self.findConfigurationParameter(configRefs, name, 0, regex)
#        return self.replaceConfigurationValue(configObjs,value,local,backupDirectory)
    
#    def replaceConfigurationValueByServer(self,serverName,name,value,regex=False,local=False,backupDirectory=None):
#        configRefs = self.getServerRefs(serverName,regex)
#        configObjs = self.findConfigurationParameter(configRefs, name, 0, regex)
#        return self.replaceConfigurationValue(configObjs,value,local,backupDirectory)
    
    def getServerRefsByFacility(self,facility,regex=False):
        serverService = self.__ts.server.ServerService
        filter = Filter()
        serverList = []
        for facilityRef in self.getFacilityRefs(facility,regex):
            filter.expression = 'device_facility_id IN %s' % facilityRef.id
            serverList = serverList + list(serverService.findServerRefs(filter))
        return serverList
    
    def getServerRefsByCustomer(self,customer,regex=False):
        serverService = self.__ts.server.ServerService
        filter = Filter()
        serverList = []
        for customerRef in self.getCustomerRefs(customer,regex):
            filter.expression = 'device_customer_id IN %s' % customerRef.id
            serverList = serverList + list(serverService.findServerRefs(filter))
        return serverList
    
    def replaceConfigurationValue(self,configurableObjectGenerator,value,scope,show,sreplace,backupDirectory):
        #updateDict = {}
        
        def updateConfigObj(configurableObject,configService):
            if backupDirectory:
                self.backupObject(os.path.join(backupDirectory,"ConfigRef-%s.ConfigurableVO" % configRef.id),configurableVO)
            for foundKey in configurableObject.foundValuesetKeys:
                if show:
                    print "BEFORE: %s = %s" % (foundKey,configurableObject.configVO.valueset[foundKey])
                if sreplace and configurableObject.searchValue:
                    configurableObject.configVO.valueset[foundKey] = re.sub(configurableObject.searchValue, value, configurableObject.configVO.valueset[foundKey])
                else:
                    configurableObject.configVO.valueset[foundKey] = value
                if show:
                    print "AFTER: %s = %s" % (foundKey,configurableObject.configVO.valueset[foundKey])
            if self.__debug:
                print "configurableObject.instances: %s" % configurableObject.instances
            if configurableObject.instances:
                appInstanceUpdateList = []
                for appInstanceIndex in configurableObject.instances:
                    appInstance = configurableObject.configVO.instances[appInstanceIndex.index]
                    for foundKey in appInstanceIndex.foundValuesetKeys:
                        if show:
                            print "BEFORE: %s = %s" % (foundKey,appInstance.valueset[foundKey])
                        if sreplace and configurableObject.searchValue:
                            appInstance.valueset[foundKey] = re.sub(configurableObject.searchValue,value,appInstance.valueset[foundKey])
                        else:
                            appInstance.valueset[foundKey] = value
                        if show:
                            print "AFTER: %s = %s" % (foundKey,appInstance.valueset[foundKey])
                    appInstanceUpdateList.append(appInstance)
                configurableObject.configVO.instances = appInstanceUpdateList
            return configService.update(configurableObject.configVO.ref,configurableObject.configVO,False,True)

        if scope == 'appconfig':
            noRef = (CustomerRef,FacilityRef,DeviceGroupRef,ServerRef)
        elif scope == 'customer':
            noRef = (ConfigurationRef,FacilityRef,DeviceGroupRef,ServerRef)
        elif scope == 'facility':
            noRef = (ConfigurationRef,CustomerRef,DeviceGroupRef,ServerRef)
        elif scope == 'devicegroup':
            noRef = (ConfigurationRef,CustomerRef,FacilityRef,ServerRef)
        elif scope == 'server':
            noRef = (ConfigurationRef,CustomerRef,DeviceGroupRef,FacilityRef)
        elif scope == 'all':
            noRef = ()
        else:
            raise ValueError,"scope %s was not in the list appconfig,customer,facility,devicegroup,server,or all." % scope
        for configObj in configurableObjectGenerator:
            if self.__debug:
                print "ref: %s" % configObj.configVO.ref
                print "instances: %s" % configObj.instances
            if not isinstance(configObj.configVO.ref,noRef):
                if isinstance(configObj.configVO.ref,ConfigurationRef):
                    configService = self.__ts.acm.ConfigurationService
                elif isinstance(configObj.configVO.ref,ServerRef):
                    configService = self.__ts.server.ServerService
                elif isinstance(configObj.configVO.ref,FacilityRef):
                    configService = self.__ts.locality.FacilityService
                elif isinstance(configObj.configVO.ref,CustomerRef):
                    configService = self.__ts.locality.CustomerService
                elif isinstance(configObj.configVO.ref,DeviceGroupRef):
                    configService = self.__ts.device.DeviceGroupService
                #if configObj.foundValuesetKeys:
                    #updateDict[configObj.configVO.ref] = updateConfigObj(configObj,configService)
                if show:
                    print "%s" % configObj.configVO.ref
                yield updateConfigObj(configObj,configService)
                #else:
                #    updateDict[configObj.configVO.ref] = None
            # else:
            #   updateDict[configRef] = None
        #return updateDict

    def cloneConfigurationRef(self,srcConfigurationRefName,newConfigurationRefName,regex=False):
        configService = self.__ts.acm.ConfigurationService
        from pytwist.com.opsware.acm import UniqueNameException
        configRef = self.getConfigurationRefs(srcConfigurationRefName,regex)
        if len(configRef) > 1:
            raise MultipleObjectRefsFound,configRef
        if not newConfigurationRefName:
            raise NameNotSpecified,newConfigurationRefName
        duplicateConfigVO = configService.getConfigurationVOs(configRef)[0]
        duplicateConfigurableVO = configService.getConfigurableVOs(configRef)[0]
        try:
            if self.isHPSA9x():
                (folder_path,node_name) = os.path.split(newConfigurationRefName)
                duplicateConfigVO.name = node_name
                duplicateConfigVO.ref = None
                if self.__debug:
                    print "folder_path: %s" % folder_path
                if folder_path:
                    folder_path_ref = self.getFolderRefs(folder_path)[0]
                else:
                    folder_path_ref = configService.getConfigurationVO(configRef[0]).folder
                    #folder_path_ref = self.getFolderRefs("/")[0]
                duplicateConfigVO.folder = folder_path_ref 
                newConfigVO = configService.create(duplicateConfigVO)
                if not configService.update(newConfigVO.ref,duplicateConfigurableVO,False,True):
                    raise CouldNotCreateSAObject,[srcConfigurationRefName,newConfigurationRefName]
            else:
                duplicateConfigVO.name = newConfigurationRefName
                duplicateConfigVO.ref = None
                newConfigVO = configService.create(duplicateConfigVO)
                if not configService.update(newConfigVO.ref,duplicateConfigurableVO,False,True):
                    raise CouldNotCreateSAObject,[srcConfigurationRefName,newConfigurationRefName]
        except UniqueNameException:
            raise ObjectAlreadyExists,newConfigurationRefName
        return newConfigVO.ref

    def updateConfigurationPlatform(self,configName,platformNames,regex=False):
        try:
            configService = self.__ts.acm.ConfigurationService
            cmlService = self.__ts.acm.CMLService
            configrefs = self.getConfigurationRefs(configName,regex)
            configvos = configService.getConfigurationVOs(configrefs)
            platforms = self.getPlatformRefs(platformNames,regex)
            configvolist = []
            for configvo in configvos:
                for cml in configvo.cmls:
                    cmlvo = cmlService.getCMLVO(cml.ref)
                    cmlvo.setPlatforms( platforms )
                    maskout = cmlService.update(cmlvo.ref,cmlvo,False,True)
                configvo.setPlatforms( platforms )
                configvolist.append( configService.update(configvo.ref,configvo,True,True) )
            return configvolist
        except IllegalValueException,args:
            raise InvalidSearchExpression,args
        except PlatformConstraintException,args:
            raise PlatformMismatchException,args

    def addConfigurationPlatform(self,configName,platformNames,regex=False):
        try:
            configService = self.__ts.acm.ConfigurationService
            cmlService = self.__ts.acm.CMLService
            configrefs = self.getConfigurationRefs(configName,regex)
            configvos = configService.getConfigurationVOs(configrefs)
            platforms = self.getPlatformRefs(platformNames,regex)
            configvolist = []
            for configvo in configvos:
                for cml in configvo.cmls:
                    cmlvo = cmlService.getCMLVO(cml.ref)
                    cmlvo.setPlatforms( list(configvo.platforms) + platforms )
                    maskout = cmlService.update(cmlvo.ref,cmlvo,False,True)
                configvo.setPlatforms( platforms + list(configvo.platforms) )
                configvolist.append( configService.update(configvo.ref,configvo,True,True) )
            return configvolist
        except IllegalValueException,args:
            raise InvalidSearchExpression,args
        except PlatformConstraintException,args:
            raise PlatformMismatchException,args

    def getCMLRefs(self,cmlid,regex=False):
        if not cmlid:
            raise NullSearchValue,"getCMLRefs"
        if type(cmlid) == str:
            if re.match('^[ \t]+$',cmlid):
                raise NullSearchValue,"cmlid"
        return self.__filterByFolderPath(   objectString=cmlid,
                                            objectService=self.__ts.acm.CMLService,
                                            searchType='cml',
                                            findMethod='findCMLRefs',
                                            objectRef=CMLRef,
                                            regex=regex,
                                            nameAttribute='\.name'  )
    
    def getCMLVOs(self,cmlid,regex=False):
        cmlservice = self.__ts.acm.CMLService
        cmlrefs = self.getCMLRefs(cmlid,regex)
        return cmlservice.getCMLVOs(cmlrefs)

    def updateCMLPlatform(self,cmlName,platformNames,regex=False):
        try:
            cmlService = self.__ts.acm.CMLService
            cmlvos = self.getCMLVOs(cmlName,regex)
            platforms = self.getPlatformRefs(platformNames,regex)
            cmlvolist = []
            for cmlvo in cmlvos:
                cmlvo.setPlatforms( platforms )
                cmlvolist.append( cmlService.update(cmlvo.ref,cmlvo,True,True) )
            return cmlvolist
        except IllegalValueException,args:
            raise InvalidSearchExpression,args
        except PlatformConstraintException,args:
            raise PlatformMismatchException,args

    def addCMLPlatform(self,cmlName,platformNames,regex=False):
        try:
            cmlService = self.__ts.acm.CMLService
            cmlvos = self.getCMLVOs(cmlName,regex)
            platforms = self.getPlatformRefs(platformNames,regex)
            cmlvolist = []
            for cmlvo in cmlvos:
                cmlvo.setPlatforms( platforms + list(cmlvo.platforms) )
                cmlvolist.append( cmlService.update(cmlvo.ref,cmlvo,True,True) )
            return cmlvolist
        except IllegalValueException,args:
            raise InvalidSearchExpression,args
        except PlatformConstraintException,args:
            raise PlatformMismatchException,args

    def getCMLInstructionValueByKeyPattern(self,cmlid,instructionKeyPattern):
        cmlservice = self.__ts.acm.CMLService
        cmlrefs = self.getCMLRefs(cmlid)
        cmlvos = cmlservice.getCMLVOs(cmlrefs)
        instructionDict = {}
        for cmlvo in cmlvos:
            tmpbuffer = cmlvo.text.split('\n')
            tmpinstdict = {}
            for line in tmpbuffer:
                instructionTag = re.search('(@!)([^@]*)(@)',line)
                if instructionTag:
                    instructions = instructionTag.group(2).split(';')
                    for instruction in instructions:
                        if re.search("%s=.*" % instructionKeyPattern,instruction):
                            key,value = instruction.split('=')
                            value = value.strip('"|\'')
                            tmpinstdict["%s" % key] = value
                    instructionDict["%s" % cmlvo.ref] = tmpinstdict
        return instructionDict
    
    def getCMLInstruction(self,cmlid,key):
        cmlkeydict = {}
        for cmlref,filepath in self.getCMLInstructionValueByKeyPattern(cmlid,key).iteritems():
            cmlkeydict[cmlref] = filepath[key]
        return cmlkeydict

    def getCMLFileNameKey(self,cmlid):
        return self.getCMLInstruction(cmlid,'filename-key')
    
    def getCMLFileDefaultKey(self,cmlid):
        return self.getCMLInstruction(cmlid,'filename-default')
    
    def getCMLNamespaceKey(self,cmlid):
        return self.getCMLInstruction(cmlid,'namespace')

    def getServerAppInstances(self,serverids,regex=False):
        ss = self.__ts.server.ServerService
        serverrefs = self.getServerRefs(serverids,regex)
        appinstanceDict = {}
        for serverref in serverrefs:
            appinstanceDict["%s" % serverref] = ss.getApplicationInstances(serverref)
        return appinstanceDict

    def getServerAppConfigs(self,serverids,regex=False):
        ss = self.__ts.server.ServerService
        serverrefs = self.getServerRefs(serverids,regex)
        appconfigDict = {}
        for serverref in serverrefs:
            cVOs = ss.getScopedConfigurableVOs(serverref)
            appconfigDict["%s" % serverref] = [ cVO for cVO in cVOs if isinstance(cVO.ref,ConfigurationRef) ]
        return appconfigDict

    def __getCMLObjectsFromConfigurationRefs(self,configurationid,regex,ref):
        cmlservice = self.__ts.acm.CMLService
        configservice = self.__ts.acm.ConfigurationService
        configrefs = self.getConfigurationRefs(configurationid,regex)
        configvos = configservice.getConfigurationVOs(configrefs)
        apptmplDict = {}
        for configvo in configvos:
            if ref:
                if configvo.cmls:
                    apptmplDict[configvo.ref] = [ cml.ref for cml in configvo.cmls ]
                else:
                    apptmplDict[configvo.ref] = configvo.cmls
            else:
                if configvo.cmls:
                    apptmplDict[configvo.ref] = [ cmlvo for cmlvo in cmlservice.getCMLVOs([ cml.ref for cml in configvo.cmls ]) ]
                else:
                    apptmplDict[configvo.ref] = configvo.cmls
        return apptmplDict
    
    def getCMLVOsFromConfigurationRefs(self,configurationid,regex=False):
        return self.__getCMLObjectsFromConfigurationRefs(configurationid,regex,ref=False)
        
    def getCMLRefsFromConfigurationRefs(self,configurationid,regex=False):
        return self.__getCMLObjectsFromConfigurationRefs(configurationid,regex,ref=True)
    
    def getFilePathFromConfigurationRefs(self,configurationid,regex=False):
        configurationRefs = self.getConfigurationRefs(configurationid)
        configValueSet = self.findConfigurationParameter(configurationRefs,None,None,None,returnDict=True)
        configCMLRefs = self.getCMLRefsFromConfigurationRefs(configurationid)
        configrefdict = {}
        for configref,cmlrefs in configCMLRefs.iteritems():
            #print "configref: %s" % configref
            cmlrefdict = {}
            if cmlrefs:
                for cmlref in cmlrefs:
                    filename_key = self.getCMLFileNameKey(cmlref.id).values()
                    if filename_key:
                        valuekey = filename_key[0]
                        if configValueSet[configref].has_key(valuekey):
                            #print "%s: %s" % (cmlref,configValueSet[configref][valuekey])
                            cmlrefdict[cmlref] = configValueSet[configref][valuekey]
                        else:
                            filename = self.getCMLFileDefaultKey(cmlref.id).values()
                            if filename:
                                #print "%s: %s" % (cmlref,filename[0]['filename-default'])
                                cmlrefdict[cmlref] = filename[0]
                            else:
                                print "%s: None" % cmlref
                                cmlrefdict[cmlref] = None

                    else:
                        filename = self.getCMLFileDefaultKey(cmlref.id).values()
                        if filename:
                            #print "%s: %s" % (cmlref,filename[0]['filename-default'])
                            cmlrefdict[cmlref] = filename[0]
                        else:
                            #print "%s: None" % cmlref
                            cmlrefdict[cmlref] = None
                configrefdict[configref] = cmlrefdict
            else:
                #print "%s: cmlrefs is None." % cmlref
                configrefdict[configref] = None
        return configrefdict

    def backupObject(self,filename,saObject):
        (directory,file) = os.path.split(filename)
        if self.__debug:
            print "directory: %s" % directory
            print "file: %s" % file
        if not os.path.exists(directory) and not directory:
            os.mkdir(directory)
        else:
            if not os.path.isdir(directory):
                raise OSError,os.strerror(errno.ENOTDIR)
            
        bfd = open(filename,'w')
        try:
            cPickle.dump(saObject,bfd)
            bfd.close()
            return True
        except:
            bfd.close()
            raise SerializationException
        
    def restoreObject(self,filename):
        rfd = open(filename,'r')
        saObject = cPickle.load(rfd)
        rfd.close()
        return saObject

    def updateUnitVO(self,unit,attributeName,attributeValue):
        us = self.__ts.pkg.UnitService
        unitRef = self.getUnitRefs(unit)
        if len(unitRef) > 1:
            raise MultipleObjectRefsFound,unitRef
        unitVO = us.getUnitVOs(unitRef)[0]
        if hasattr(unitVO,attributeName):
            #if self.isHPSA9x():
            #    setAttributeMethod = eval("unitVO.set%s" % attributeName)
            #    setAttributeMethod(attributeValue)
            #else:
            #if isinstance(attributeValue,str):
            eval("unitVO.__setattr__")(attributeName,attributeValue)
            #else:
            #    eval("unitVO.__setattr__('%s',%s)" % (attributeName,attributeValue))
            try:
                updatedUnitVO = us.update(unitVO.ref,unitVO,False,True)
            except TwistInstantiationException,args:
                raise IncorrectObjectRef,args.cause.message
            return updatedUnitVO
        else:
            raise AttributeError,attributeName

    def __getUnitVOs(self,unitName,regex=False):
        unitService = self.__ts.pkg.UnitService
        unitrefs = self.getUnitRefs(unitName,regex)
        return unitService.getUnitVOs(unitrefs)
    
    def updateUnitPlatform(self,unitName,platformNames,regex=False):
        try:
            unitService = self.__ts.pkg.UnitService
            unitvos = self.__getUnitVOs(unitName,regex)
            unitvolist = []
            for unitvo in unitvos:
                unitvo.platforms = self.getPlatformRefs(platformNames,regex)
                unitvolist.append(unitService.update(unitvo.ref,unitvo,True,True))
            return unitvolist
        except IllegalValueException,args:
            raise InvalidSearchExpression,args

    def addUnitPlatform(self,unitName,platformNames,regex=False):
        try:
            unitService = self.__ts.pkg.UnitService
            unitvos = self.__getUnitVOs(unitName,regex)
            unitvolist = []
            platformrefs = self.getPlatformRefs(platformNames,regex)
            for unitvo in unitvos:
                unitvo.platforms = list(unitvo.platforms) + platformrefs
                unitvolist.append(unitService.update(unitvo.ref,unitvo,True,True))
            return unitvolist
        except IllegalValueException,args:
            raise InvalidSearchExpression,args

#        twistHandle = self.__ts
#        unitRefRepr = re.sub("(.*\()([A-Za-z]+\:[0-9]*[^)])(\\).*)","\\2","%s" % unitRef)
#        if self.__debug:
#            print "unitRefRepr: %s" % unitRefRepr
#        (unitRefString,unitId) = re.split(":",unitRefRepr)
#        unitService = re.sub("Ref","Service",objRefString)
#        (objRootModulePath,objModule) = os.path.splitext(policyItemRef.__module__)

    def setCustomAttributeOnSoftwarePolicy(self,spolicy,key,value,regex=False):
        spolicyService = self.__ts.swmgmt.SoftwarePolicyService
        spolicyRef = self.getSoftwarePolicyRefs(spolicy,regex)
        successfulSpolicyRefs = []
        for spref in spolicyRef:
            try:
                spolicyService.setCustAttr(spref,key,value)
                successfulSpolicyRefs.append(spref)
            except NotFoundException,args:
                raise NotFoundException,args
                continue
        return successfulSpolicyRefs
    
    def getCustomAttributesOnSoftwarePolicy(self,spolicy,regex=False):
        spolicyService = self.__ts.swmgmt.SoftwarePolicyService
        spolicyRef = self.getSoftwarePolicyRefs(spolicy,regex)
        spolicycadict = {}
        for spref in spolicyRef:
            try:
                spolicycadict[spref] = spolicyService.getCustAttrs(spref,None,False)
            except NotFoundException,args:
                raise NotFoundException,args
                continue
        return spolicycadict
    
    def setCustomAttributesOnServer(self,server,key,value,regex=True):
        serverService = self.__ts.server.ServerService
        serverRefs = self.getServerRefs(server,regex)
        successfulServerRefs = []
        for sref in serverRefs:
            try:
                serverService.setCustAttr(sref,key,value)
                successfulServerRefs.append(sref)
            except NotFoundException,args:
                raise NotFoundException,args
                continue
        return successfulServerRefs

    def setCustomAttributesOnServerByServerRefs(self,serverRefs,key,value):
        serverService = self.__ts.server.ServerService
        successfulServerRefs = []
        for sref in serverRefs:
            try:
                serverService.setCustAttr(sref,key,value)
                successfulServerRefs.append(sref)
            except NotFoundException,args:
                raise NotFoundException,args
                continue
        return successfulServerRefs
    
    def getCustomAttributesOnServer(self,server,regex=False):
        serverService = self.__ts.server.ServerService
        serverRefs = self.getServerRefs(server,regex)
        servercadict = {}
        for sref in serverRefs:
            try:
                servercadict[sref] = serverService.getCustAttrs(sref,None,False)
            except NotFoundException,args:
                raise NotFoundException,args
                continue
        return servercadict

    def getCustomAttributesOnServerByServerRefs(self,serverRefs):
        serverService = self.__ts.server.ServerService
        servercadict = {}
        for sref in serverRefs:
            try:
                servercadict[sref] = serverService.getCustAttrs(sref,None,False)
            except NotFoundException,args:
                raise NotFoundException,args
                continue
        return servercadict
        
    def removeCustomAttributeOnSoftwarePolicy(self,spolicy,key,regex=False):
        spolicyService = self.__ts.swmgmt.SoftwarePolicyService
        spolicyRef = self.getSoftwarePolicyRefs(spolicy,regex)
        for spref in spolicyRef:
            try:
                spolicyService.removeCustAttr(spref,key)
                yield spref
            except NotFoundException,args:
                raise NotFoundException,args
                continue

    def isPolicyItemInSoftwarePolicyPlatform(self,spolicy,policyItemRef):
        if isinstance(policyItemRef,ServerScriptRef):
            return True
        twistHandle = self.__ts
        spolicyService = self.__ts.swmgmt.SoftwarePolicyService
        spolicyRef = self.getSoftwarePolicyRefs(spolicy)[0]
        objRefRepr = re.sub("(.*\()([A-Za-z]+\:[0-9]*[^)])(\\).*)","\\2","%s" % policyItemRef)
        if self.__debug:
            print "objRefRepr: %s" % objRefRepr
        (objRefString,objId) = re.split(":",objRefRepr)
        objService = re.sub("Ref","Service",objRefString)
        (objRootModulePath,objModule) = os.path.splitext(policyItemRef.__module__)
        objService = objModule + "." + objService
        objGetVO = re.sub("Ref","VO",objRefString)
        objGetVO = "get" + objGetVO
        if self.__debug:
            print "objService: %s" % objService
            print "objGetVO: %s" % objGetVO
        try:
            policyItemSet = Set(eval("twistHandle%s.%s" % (objService,objGetVO))(policyItemRef).platforms)
            spolicySet = Set(spolicyService.getSoftwarePolicyVO(spolicyRef).platforms)
        except NotFoundException,args:
            raise NotFoundException,args
        return spolicySet.intersection(policyItemSet)

    def isSoftwarePolicyinServerPlatform(self,serverRefList,spolicyRefList):
        spolicyService = self.__ts.swmgmt.SoftwarePolicyService
        serverService = self.__ts.server.ServerService
        for serverRef in serverRefList:
            if not isinstance(serverRef,ServerRef):
                raise InvalidObjectRef,serverRef
            for spolicyRef in spolicyRefList:
                if not isinstance(spolicyRef,SoftwarePolicyRef):
                    raise InvalidObjectRef,spolicyRef
                spolicyPlatforms = spolicyService.getSoftwarePolicyVO(spolicyRef).platforms
                serverPlatform = serverService.getServerVO(serverRef).platform
                if not serverPlatform in spolicyPlatforms:
                    raise PlatformMismatchException,serverRef,spolicyRef
        return True

    def addSoftwarePolicyItem(self,spolicy,policyItemRefList,policyItemIndex=None,RPMremediateMode="ALWAYS",RPMupdateMode="NONE"):
        spolicyService = self.__ts.swmgmt.SoftwarePolicyService 
        if self.__debug:
            print "PolicyItemIndex: %s" % policyItemIndex
        if policyItemIndex:
            if isinstance(policyItemIndex,str):
                if not re.match('[0-9]+',policyItemIndex):
                    raise InvalidArgs,policyItemIndex
                policyItemIndex = int(policyItemIndex) - 1 
            else:
                policyItemIndex = policyItemIndex - 1
        spolicyItemList = []
        spolicyRef = self.getSoftwarePolicyRefs(spolicy)
        if len(spolicyRef) > 1:
            raise MultipleObjectRefsFound,spolicyRef
        spolicyVO = spolicyService.getSoftwarePolicyVO(spolicyRef[0])
        installableItemDataList = list(spolicyVO.installableItemData)
        uninstallableItemDataList = list(spolicyVO.uninstallableItemData)
        softwarePolicyItemList = list(spolicyVO.softwarePolicyItems)
        for newItem in policyItemRefList:
            if not isinstance(newItem,softwarePolicyItemDataRefs):
                raise NotSoftwarePolicyItem,newItem
            if softwarePolicyItemList.count(newItem) != 0:
                raise DuplicatePolicyItemFound,newItem
        for policyItemRef in policyItemRefList:
            if self.isPolicyItemInSoftwarePolicyPlatform(spolicy,policyItemRef):
                if isinstance(policyItemRef,RPMRef):
                    spolicyItem = SoftwarePolicyRPMItemData()
                    spolicyItem.remediateMode = RPMremediateMode 
                    spolicyItem.updateMode = RPMupdateMode
                    spolicyItem.policyItem = policyItemRef
                elif isinstance(policyItemRef,ServerScriptRef):
                    spolicyItem = SoftwarePolicyScriptItemData()
                    spolicyItem.policyItem = policyItemRef
                else:
                    spolicyItem = SoftwarePolicyItemData()
                    spolicyItem.policyItem = policyItemRef
                if self.__debug:
                    print "spolicyItem: %s" % spolicyItem
                    print "spolicyItem.policyItem: %s" % spolicyItem.policyItem
                spolicyItemList.append(spolicyItem)
            else:
                raise PlatformMismatchException,policyItemRef
        if self.__debug:
            print "before if else PolicyItemIndex: %s" % policyItemIndex
        if not isinstance(policyItemIndex,int):
            installableItemDataList = installableItemDataList + spolicyItemList
            uninstallableItemDataList = uninstallableItemDataList + \
                    [ i for i in spolicyItemList if not isinstance(i.policyItem,(ServerScriptRef,ConfigurationRef))]
            softwarePolicyItemList = softwarePolicyItemList + policyItemRefList
            if self.__debug:
                print "installableItemDataList: %d" % len(installableItemDataList)
                print "uninstallableItemDataList: %d" % len(uninstallableItemDataList)
                print "softwarePolicyItemList: %d" % len(softwarePolicyItemList)
        else:
            if self.__debug:
                print "in else PolicyItemIndex: %s" % policyItemIndex
            for indexAdd in range(0,len(policyItemRefList)):
                if self.__debug:
                    print "index: %d" % (policyItemIndex + indexAdd)
                installableItemDataList.insert(policyItemIndex + indexAdd, spolicyItemList[indexAdd])   
                if self.__debug:
                    print "uninstallableIndex: %d" % (policyItemIndex + indexAdd)
                    print "len uninstallableIndex: %d" % (len(uninstallableItemDataList) - 1)
                if (policyItemIndex + indexAdd) > (len(uninstallableItemDataList) - 1):
                    uninstallableItemDataList.insert(len(uninstallableItemDataList) - 1, spolicyItemList[indexAdd]) 
                else:
                    uninstallableItemDataList.insert(policyItemIndex + indexAdd, spolicyItemList[indexAdd]) 
                softwarePolicyItemList.insert(policyItemIndex + indexAdd, policyItemRefList[indexAdd])
        spolicyVO.installableItemData = installableItemDataList
        spolicyVO.uninstallableItemData = uninstallableItemDataList
        spolicyVO.softwarePolicyItems = softwarePolicyItemList
        return spolicyService.update(spolicyRef[0],spolicyVO,False,True)

    def modifySoftwarePolicyItembyName(self,spolicy,oldPolicyItem,newPolicyItem,action,RPMremediateMode="ALWAYS",RPMupdateMode="NONE"):
        spolicyService = self.__ts.swmgmt.SoftwarePolicyService
        if action == 'replace':
            if not isinstance(newPolicyItem,softwarePolicyItemDataRefs):
                raise NotSoftwarePolicyItem,newPolicyItem
        spolicyRef = self.getSoftwarePolicyRefs(spolicy)
        if len(spolicyRef) > 1:
            raise MultipleObjectRefsFound,spolicyRef
        spolicyVO = spolicyService.getSoftwarePolicyVO(spolicyRef[0])
        installableItemDataList = list(spolicyVO.installableItemData)
        uninstallableItemDataList = list(spolicyVO.uninstallableItemData)
        softwarePolicyItemList = list(spolicyVO.softwarePolicyItems)
        if softwarePolicyItemList.count(newPolicyItem) != 0:
            raise DuplicatePolicyItemFound,newPolicyItem
        if oldPolicyItem in softwarePolicyItemList:
            if action == 'replace':
                if isinstance(newPolicyItem,RPMRef):
                    spolicyItem = SoftwarePolicyRPMItemData()
                    spolicyItem.remediateMode = RPMremediateMode 
                    spolicyItem.updateMode = RPMupdateMode
                    spolicyItem.policyItem = newPolicyItem
                elif isinstance(newPolicyItem,ServerScriptRef):
                    spolicyItem = SoftwarePolicyScriptItemData()
                    spolicyItem.policyItem = newPolicyItem
                else:
                    spolicyItem = SoftwarePolicyItemData()
                    spolicyItem.policyItem = newPolicyItem
            for item in installableItemDataList:
                if item.policyItem == oldPolicyItem:
                    if action == 'replace':
                        installableItemDataList[installableItemDataList.index(item)] = spolicyItem
                    else:
                        installableItemDataList.remove(item)
                    break
            for item in uninstallableItemDataList:
                if item.policyItem == oldPolicyItem:
                    if action == 'replace':
                        uninstallableItemDataList[uninstallableItemDataList.index(item)] = spolicyItem
                    else:
                        uninstallableItemDataList.remove(item)
                    break
            if action == 'replace':
                softwarePolicyItemList[softwarePolicyItemList.index(oldPolicyItem)] = newPolicyItem
            else:
                softwarePolicyItemList.remove(oldPolicyItem)
            spolicyVO.installableItemData = installableItemDataList
            spolicyVO.uninstallableItemData = uninstallableItemDataList
            spolicyVO.softwarePolicyItems = softwarePolicyItemList
            if self.__debug:
                print "installableItemDataList: %s" % installableItemDataList
                print "uninstallableItemDataList: %s" % uninstallableItemDataList
                print "softwarePolicyItemList: %s" % softwarePolicyItemList
            newspolicyVO = spolicyService.update(spolicyRef[0],spolicyVO,False,True)
            return newspolicyVO
        else:
            raise NoObjectRefFound,oldPolicyItem

    def findSoftwarePolicyItembyPosition(self,spolicy,policyItemIndex):
        spolicyService = self.__ts.swmgmt.SoftwarePolicyService
        try:
            if isinstance(policyItemIndex,str):
                if not re.match('[0-9]+',policyItemIndex):
                    raise InvalidArgs,policyItemIndex
                policyItemIndex = int(policyItemIndex) - 1 
            else:
                policyItemIndex = policyItemIndex - 1
            spolicyRef = self.getSoftwarePolicyRefs(spolicy)
            if len(spolicyRef) > 1:
                raise MultipleObjectRefsFound,spolicyRef
            spolicyVO = spolicyService.getSoftwarePolicyVO(spolicyRef[0])
            policyItem = spolicyVO.softwarePolicyItems[policyItemIndex]
        except IndexError,args:
            raise IndexError,(policyItemIndex + 1)
        return policyItem

    def findSoftwarePolicyItemsbyName(self,SoftwarePolicyID,ItemName,isExactMatch=True):
        SoftwarePolicyRef = self.getSoftwarePolicyRefs(SoftwarePolicyID)[0]
        SoftwarePolicyItems = []
        SoftwarePolicyService = self.__ts.swmgmt.SoftwarePolicyService
        SoftwarePolicyVO = SoftwarePolicyService.getSoftwarePolicyVO(SoftwarePolicyRef)
        for item in SoftwarePolicyVO.softwarePolicyItems:
            if self.__debug: print "Checking item name [" + item.name + "] with input name ["  + ItemName + "] Exact Match [" + str(isExactMatch) + "]"
            if isExactMatch:
                if item.name == ItemName:
                    SoftwarePolicyItems.append(item)
                    if self.__debug: print "Found item [" + item.name + "]"
            else:
                if (re.match(ItemName,item.name,re.IGNORECASE)):
                    SoftwarePolicyItems.append(item)
                    if self.__debug: print "Found item [" + item.name + "]"
        return SoftwarePolicyItems

    def replaceSoftwarePolicyItembyPosition(self,spolicy,newPolicyItem,policyItemIndex):
        oldPolicyItem = self.findSoftwarePolicyItembyPosition(spolicy,policyItemIndex)
        spolicyVO = self.modifySoftwarePolicyItembyName(spolicy,oldPolicyItem,newPolicyItem,'replace')
        return spolicyVO

    def deleteSoftwarePolicyItembyPosition(self,spolicy,policyItemIndex):
        policyItemtoDelete = self.findSoftwarePolicyItembyPosition(spolicy,policyItemIndex)
        spolicyVO = self.modifySoftwarePolicyItembyName(spolicy,policyItemtoDelete,None,'delete')
        return spolicyVO

    def listSoftwarePolicyItems(self,spolicy,regex=False):
        spolicyService = self.__ts.swmgmt.SoftwarePolicyService
        spolicyRefs = self.getSoftwarePolicyRefs(spolicy)
        spolicyItems = {}
        for spolicyRef in spolicyRefs:
            spolicyVO = spolicyService.getSoftwarePolicyVO(spolicyRef)
            spolicyItems[spolicyRef] = spolicyVO.softwarePolicyItems
        return spolicyItems

    def createSoftwarePolicy(self,folderName,spolicyName,platformNames=None,policyItemRefs=None,regex=False,locked=False,template=False,lifecycle='AVAILABLE'):
        spolicyService = self.__ts.swmgmt.SoftwarePolicyService
        folderRefs = self.getFolderRefs(folderName)
        if len(folderRefs) > 1:
            raise MultipleObjectRefsFound,folderRefs
        spolicyVO = SoftwarePolicyVO()
        if platformNames:
            if regex:
                spolicyVO.platforms = self.getPlatformRefs(platformNames,True)
            else:
                spolicyVO.platforms = self.getPlatformRefs(platformNames)
        else:
            spolicyVO.platforms = self.getPlatformRefs("OS Independent")
        spolicyVO.name = spolicyName
        spolicyVO.folder = folderRefs[0]
        spolicyVO.lifecycle = lifecycle
        spolicyVO = spolicyService.create(spolicyVO)
        #if self.__debug:
        print "spolicyVO.ref.name: %s" % spolicyVO.ref.name
        if policyItemRefs:
            spolicyVO = self.addSoftwarePolicyItem(spolicyVO.ref.id,policyItemRefs)
        return spolicyVO
    
    def __getSoftwarePolicyVOs(self,spolicyName,regex=False):
        spolicyService = self.__ts.swmgmt.SoftwarePolicyService
        spolicyrefs = self.getSoftwarePolicyRefs(spolicyName,regex)
        return spolicyService.getSoftwarePolicyVOs(spolicyrefs)
    
    def updateSoftwarePolicyPlatform(self,spolicyName,platformNames,regex=False):
        try:
            spolicyService = self.__ts.swmgmt.SoftwarePolicyService
            spolicyvos = self.__getSoftwarePolicyVOs(spolicyName,regex)
            spolicyVO = SoftwarePolicyVO()
            spolicyVO.platforms = self.getPlatformRefs(platformNames,regex)
            return [ spolicyService.update(spolicyvo.ref,spolicyVO,True,True) for spolicyvo in spolicyvos ]
        except IllegalValueException,args:
            raise InvalidSearchExpression,args

    def addSoftwarePolicyPlatform(self,spolicyName,platformNames,regex=False):
        try:
            spolicyService = self.__ts.swmgmt.SoftwarePolicyService
            spolicyvos = self.__getSoftwarePolicyVOs(spolicyName,regex)
            spolicyVO = SoftwarePolicyVO()
            spolicyVO.platforms = self.getPlatformRefs(platformNames,regex)
            spolicyvolist = []
            for spolicyvo in spolicyvos:
                spolicyVO.platforms = spolicyVO.platforms + list(spolicyvo.platforms)
                spolicyvolist.append(spolicyService.update(spolicyvo.ref,spolicyVO,True,True))
            return spolicyvolist
        except IllegalValueException,args:
            raise InvalidSearchExpression,args

    def getServerRefsBySoftwarePolicy(self,softwarePolicy,regex):
        spolicyService = self.__ts.swmgmt.SoftwarePolicyService
        spolicyRefs = self.getSoftwarePolicyRefs(softwarePolicy,regex)
        policyToServerMap = {}
        for spolicyRef in spolicyRefs:
            policyToServerMap[spolicyRef] = [  pa.policyAttachable for pa in spolicyService.getPolicyAttachableAssociations([spolicyRef]) ]
        return policyToServerMap

    def isHPSA9x(self):
        twistConsole = self.__ts.shared.TwistConsoleService
        (major,minor,patch) = re.split('\.',twistConsole.getAPIVersion())
        if int(major) >= 42:
            return True
        else:
            return False

    def installSoftwarePolicy(self,attachableRefList,spolicyRefs):
        if len(attachableRefList) == 0:
            raise NoObjectRefFound,"empty ServerRef or DeviceGroupRef list"
        if len(spolicyRefs) == 0:
            raise NoObjectRefFound,"empty SoftwarePolicyRef list"
        spolicyService = self.__ts.swmgmt.SoftwarePolicyService
        try:
            spolicyService.attachToPolicies(spolicyRefs,attachableRefList)
            jobRef = spolicyService.startRemediateNow(spolicyRefs,attachableRefList)
        except PlatformConstraintException,args:
            raise PlatformConstraintException,args 
        except AuthorizationDeniedException,args:
            raise AuthorizationDeniedException,args
        return jobRef
    
    def installSoftwarePolicyOnServers(self,server,spolicy,regex=False):
        serverrefs = self.getServerRefs(server,regex)
        spolicyrefs = self.getSoftwarePolicyRefs(spolicy,regex)
        return self.installSoftwarePolicy(serverrefs,spolicyrefs)
    
    def installSoftwarePolicyOnDeviceGroups(self,dvcgroup,spolicy,regex=False):
        dvcgrouprefs = self.getDeviceGroupRefs(dvcgroup,regex)
        spolicyrefs = self.getSoftwarePolicyRefs(spolicy,regex)
        return self.installSoftwarePolicy(dvcgrouprefs,spolicyrefs)
    
    def installSoftwarePolicyViaServerGroupMembers(self,servergroup,spolicy,regex=False):
        serverrefs = self.getServerGroupInfo(servergroup)['devices']
        spolicyrefs = self.getSoftwarePolicyRefs(spolicy,regex)
        return self.installSoftwarePolicy(serverrefs,spolicyrefs)

    def uninstallSoftwarePolicy(self,attachableRefList,spolicyRefs):
        if len(attachableRefList) == 0:
            raise NoObjectRefFound,"empty ServerRef or DeviceGroupRef list"
        if len(spolicyRefs) == 0:
            raise NoObjectRefFound,"empty SoftwarePolicyRef list"
        spolicyService = self.__ts.swmgmt.SoftwarePolicyService
        serverService = self.__ts.server.ServerService
        try:
            uninstallJobArgs = SoftwareUninstallJobArgument()
            iae = InstallableAttachableEntry()
            iae.installables = spolicyRefs
            iae.policyAttachables = attachableRefList
            jobNotify = JobNotification()
            jobNotify.onFailureOwner = ''
            jobNotify.onSuccessOwner = ''
            jobNotify.onFailureRecipients = ['']
            jobNotify.onSuccessRecipients = ['']
            uninstallJobArgs.installableAttachableEntries = [ iae ]
            uninstallJobArgs.notificationSpec = jobNotify
            uninstallJobArgs.analyzePhaseArguments = AnalyzeArgument()
            uninstallJobArgs.actionPhaseArguments = ActionArgument()
            jobRef = spolicyService.startUninstallSoftware(uninstallJobArgs)
        except PlatformConstraintException,args:
            raise PlatformConstraintException,args 
        except AuthorizationDeniedException,args:
            raise AuthorizationDeniedException,args
        return jobRef
    
    def uninstallSoftwarePolicyOnServers(self,server,spolicy,regex=False):
        serverrefs = self.getServerRefs(server,regex)
        spolicyrefs = self.getSoftwarePolicyRefs(spolicy,regex)
        return self.uninstallSoftwarePolicy(serverrefs,spolicyrefs)
    
    def uninstallSoftwarePolicyOnDeviceGroups(self,dvcgroup,spolicy,regex=False):
        dvcgrouprefs = self.getDeviceGroupRefs(dvcgroup,regex)
        spolicyrefs = self.getSoftwarePolicyRefs(spolicy,regex)
        return self.uninstallSoftwarePolicy(dvcgrouprefs,spolicyrefs)

    def uninstallSoftwarePolicyViaServerGroupMembers(self,servergroup,spolicy,regex=False):
        serverrefs = self.getServerGroupInfo(servergroup)['devices']
        spolicyrefs = self.getSoftwarePolicyRefs(spolicy,regex)
        return self.uninstallSoftwarePolicy(serverrefs,spolicyrefs)

    def cacheRefresh(self):
        legacyTwistService = self.__ds.TwistServer
        legacyTwistService.forceCacheConsistency()
    
    
    
    # Internal convenience method to return a [single] ServerRef for a given server name
    def __getServerRef(self, server):
        if isinstance(server, ServerRef):
            return server
        
        sref = self.getServerRefs(server)
        if len(sref) > 1:
            raise MultipleServerRefsFound("Multiple servers found for %s" % server)
        if len(sref) < 1:
            raise NoServerRefFound("No servers found for %s" % server)
        return sref[0]
    
    # returns a dictionary of ServerVO attributes
    def getServerDetails(self, server):
        sref = self.__getServerRef(server)
        vo = self.__getServerService().getServerVO(sref)
        return _getObjectAsDict(vo)
    
    # returns a dictionary of ServerHardwareVO attributes
    def getServerHardwareDetails(self, server):
        sref = self.__getServerRef(server)
        vo = self.__getServerService().getServerHardwareVO(sref)
        return _getObjectAsDict(vo)
    
    # returns a list of dictionaries w/ installed software attributes
    def getServerSoftwareDetails(self, server):
        sref = self.__getServerRef(server)
        software = self.__getServerService().getInstalledSoftware(sref)
        return [_getObjectAsDict(s) for s in software]
    
    # returns a list of dictionaries w/ physical disk attributes
    def getServerPhysicalDiskDetails(self, server):
        sref = self.__getServerRef(server)
        diskRefs = self.__getServerService().getPhysicalDisks(sref)
        return [_getObjectAsDict(d) for d in self.__getPhysicalDiskService().getPhysicalDiskVOs(diskRefs)]
    
    # returns a dictionary of PlatformVO attributes
    def getPlatformDetails(self, platform):
        return _getObjectAsDict(
                                self.__getPlatformService().getPlatformVO(platform)
                                )
    
    # returns a list of dictionaries w/ attributes of all PlatformVOs
    def getAllPlatformDetails(self):
        refs = self.getPlatformRefs("*")
        return [_getObjectAsDict(p) for p in self.__getPlatformService().getPlatformVOs(refs)]



# softwarePolicyItemDataRefs

'''
    def findConfigurationValue(self,configurationName,value,regex=False):
        configService = self.__ts.acm.ConfigurationService
        configRefs = self.getConfigurationRefs(configurationName,regex)
        configurableVOs = configService.getConfigurableVOs(configRefs)  
        dictConfigRef = {}  
        for configVO in configurableVOs:
            listNameValue = [] 
            if configVO.valueset:
                # if value in configVO.valueset.values():
                for item in configVO.valueset.iteritems():
                    if not regex:
                        if value == item[1]:
                            listNameValue.append(item)
                    else:
                        if re.match(value,item[1]):
                            listNameValue.append(item)
                if listNameValue:
                    dictConfigRef[configVO.ref] = listNameValue
        return dictConfigRef
'''
