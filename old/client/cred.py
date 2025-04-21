#!/usr/bin/python3

import requests, argparse, sys
from configparser import ConfigParser
requests.packages.urllib3.disable_warnings()
config = ConfigParser()
config.read('/etc/config.edc')
token = config.get('auth', 'token')
url = config.get('instance', 'curl')
headers = {'Authorization': 'Token {}'.format(token)}

parser = argparse.ArgumentParser(
	formatter_class=argparse.RawDescriptionHelpFormatter,
	description='''\
Example:
cred -u cmduser4 -p cmdpass4 -n hashgoeshere -f james -l tubb -r users -d keyboarder'''
	)
parser.add_argument("-u","--creduser", default="", help="(Required) enter username")
parser.add_argument("-p","--credpass", default="", help="enter password")
parser.add_argument("-n","--credhash", default="", help="enter hash")
parser.add_argument("-f","--credfirst", default="", help="enter first name")
parser.add_argument("-l","--credlast", default="", help="enter last name")
parser.add_argument("-r","--credrole", default="", help="enter a role")
parser.add_argument("-d","--creddesc", default="", help="enter a description")
args = parser.parse_args()
if not args.creduser:
	sys.exit(parser.print_help())

data = {"username":args.creduser,"passwd":args.credpass,"hashw":args.credhash,"first":args.credfirst,"last":args.credlast,"role":args.credrole,"description":args.creddesc}

requests.post(url,data=data,headers=headers,verify=False)
