#!/usr/bin/python3

import requests, argparse, sys
from configparser import ConfigParser
requests.packages.urllib3.disable_warnings()
config = ConfigParser()
config.read('/etc/config.edc')
token = config.get('auth', 'token')
url = config.get('instance', 'turl')
headers = {'Authorization': 'Token {}'.format(token)}

parser = argparse.ArgumentParser(
	formatter_class=argparse.RawDescriptionHelpFormatter,
	description='''\
Example:
target -t tgthost1 -i 192.168.0.1 -n network5 -u admin1 -d "admin workstation" -c "access to all segments"'''
	)
parser.add_argument("-t","--tgthost", default="", help="(Required) enter target hostname")
parser.add_argument("-i","--tgtip", default="", help="enter target IP")
parser.add_argument("-n","--tgtnet", default="", help="enter target network")
parser.add_argument("-u","--tgtuser", default="", help="enter target username")
parser.add_argument("-d","--tgtdesc", default="", help="enter a description")
parser.add_argument("-c","--tgtcomms", default="", help="enter comments")

args = parser.parse_args()
if not args.tgthost:
	sys.exit(parser.print_help())

data = {"host":args.tgthost,"ip":args.tgtip,"network":args.tgtnet,"users":args.tgtuser,"description":args.tgtdesc,"comments":args.tgtcomms}

requests.post(url,data=data,headers=headers,verify=False)