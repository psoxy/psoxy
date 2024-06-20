#!/bin/python3
# -*- coding: utf-8 -*-

import subprocess
import sys
from optparse import OptionParser

python_path = "python3"
server_file = "psoxy-server.py"

parser = OptionParser()
parser.add_option("-c", "--use-external-config",
                  action="store_true", dest="use_external_config", default=False,
                  help="uses the external configs in './config.py'")
parser.add_option("-v", "--verbose",
                  action="store_true", dest="verbose", default=False,
                  help="be more verbose")
parser.add_option("-p", "--start-port",
                  action="store", dest="start_port", default="2152",
                  help="set the start port")

(options, args) = parser.parse_args()

if not len(args) or int(args[0]) <= 0:
    print("You must pass number of servers to run")
    exit(-1)
else:
    _args = []
    if options.use_external_config:
        _args.append("-c")
    if options.verbose:
        _args.append("-v")
    processes = []
    try:
        for i in range(int(args[0])):
            print(f"Starting server on port '{int(options.start_port) + i}'")
            processes.append(subprocess.Popen([python_path, server_file, "-p", f"{int(options.start_port) + i}", *_args], shell=False))
        for i in range(int(args[0])):
            processes[i].communicate()
    except KeyboardInterrupt:
        print("Aborting")
    finally:
        for i in range(int(args[0])):
            processes[i].terminate()



