#!/opt/opsware/bin/python2

import os
import socket
import sys
import time

from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

def main():
    """ Connect to MongoDB """
    try:
        # older way to connect to mongo
        # c = Connection(host="owsas05x-ops-08.portal.webmd.com", port=27017)
        c = MongoClient(host="owsas05x-ops-08.portal.webmd.com", port=27017, w=0)
    except ConnectionFailure, e:
        sys.stderr.write("Could not connect to log statistics: %s\n" % e)
        sys.exit(1)

    # Get a Database handle to a database named "saclidb"
    dbh = c["saclidb"]

    # Demonstrate the db.connection property to retrieve a reference to the
    # Connection object should it go out of scope. In most cases, keeping a
    # reference to the Database object for the lifetime of your program should
    # be sufficient.

    assert dbh.connection == c
    
    # Create the statistics document
    stats = { }
    stats['command'] = sys.argv[1]
    stats['args'] =  sys.argv[2:]
    stats['user'] = os.environ['USER']
    stats['time'] = long(time.time( ))
    stats['host'] = socket.gethostname()

    dbh.saclistats.insert(stats)

if __name__ == "__main__":
    main()

