#!/usr/bin/python3

import requests, argparse, subprocess, sys, time
from datetime import datetime
from configparser import ConfigParser
requests.packages.urllib3.disable_warnings()
config = ConfigParser()
config.read('/etc/config.edc')
token = config.get('auth', 'token')
operator = config.get('auth','opid')
url = config.get('instance', 'lurl')
headers = {'Authorization': 'Token {}'.format(token)}


parser = argparse.ArgumentParser(
	formatter_class=argparse.RawDescriptionHelpFormatter,
	description='''\
Example:
log -l attacksys1 -k 43.44.54.55 -t thost1 -i 192.168.0.1 -p 0 -u http://www.domain.com -n terminal -s ping -d "ping domain.com" -c "ping -c1 www.domain.com"'''
	)
parser.add_argument("-l","--shost", default="", help="(Required) enter source host")
parser.add_argument("-k","--sip", default="", help="(Required) enter source IP")
parser.add_argument("-t","--dhost", default="", help="(Required) enter target host")
parser.add_argument("-i","--dip", default="", help="(Required) enter target IP")
parser.add_argument("-p","--dport", default="", help="(Required) enter target port")
parser.add_argument("-u","--durl", default="", help="enter target url")
parser.add_argument("-s","--ssdesc", default="", help="enter screenshot description")
parser.add_argument("-c","--cmda", default="", help="enter command")
parser.add_argument("-n","--tool", default="", help="enter tool")
parser.add_argument("-d","--desc", default="", help="enter a description")


args = parser.parse_args()
if not args.dhost:
	sys.exit(parser.print_help())

oput = subprocess.check_output(f"{args.cmda} 2>&1 |tee /dev/tty", shell=True)
dt = datetime.now()
now = dt.strftime("%Y%m%d_%H%M%S")

# Change directory user/path
file = f"/home/user/logs/screenshots/{now}_args.ssdesc_operator.png"

# Switch between nix and MacOS for screenshot
cmdc = f"gnome-screenshot -a -f {file}"
#cmdc = f"screencapture -i {file}"

subprocess.check_output(cmdc,shell=True)
print()

ssfile = {'scrsht':open(f'{file}', 'rb')}
data = {"src_host":args.shost,"src_ip":args.sip,"dst_host":args.dhost,"dst_ip":args.dip,"dst_port":args.dport,"url":args.durl,"tool":args.tool,"cmds":args.cmda,"output":oput,"operator_id":operator,"description":args.desc}
time.sleep(2)

requests.post(url,data=data,files=ssfile,headers=headers,verify=False)


