#!/usr/bin/python3
#
# watch for failed smtp login attempts and blackhole the ip
#

import re
from collections import defaultdict
import subprocess
import dbm.gnu
import sys
import operator
import getopt
from datetime import datetime,timedelta
import time
from pprint import pprint
import argparse

source 			= "/var/log/maillog"
dbfile			= "/root/smtpban.db"
# blackhole ip after this many failed logins
banThreshold	= 5
# expire the blackhole route after this many days
banPeriod	= 7

# if true, suppress all output
silentMode	= False
# if true, log blocked/unblocked IPs to stdout
verbose		= False
# --------------------------------------------------------------

class mycolors:
	"""define some constants for colored output on the shell"""
	HEADER 		= ''
	OKBLUE 		= ''
	OKGREEN 	= ''
	WARNING		= ''
	FAIL		= ''
	ENDC		= ''
	BOLD		= ''
	UNDERLINE	= ''

	def __init__(self):
		"""initialize the class attributes to only use colour escape sequences when on a tty"""
		if sys.stdout.isatty():
			self.HEADER = '\033[95m'
			self.OKBLUE = '\033[94m'
			self.OKGREEN = '\033[92m'
			self.WARNING = '\033[93m'
			self.FAIL = '\033[91m'
			self.ENDC = '\033[0m'
			self.BOLD = '\033[1m'
			self.UNDERLINE = '\033[4m'

			

# --------------------------------------------------------------
def print(*args, **kwargs):
	"""Override the print function to suppress output in silentMode"""
	if not silentMode:
		return __builtins__.print(*args, **kwargs)

# --------------------------------------------------------------
def getFailedLogins(file):
	"""return a dictionary with a list of (dates of...) failed login attempts (= values) for each ip (= keys)"""
	failedLogins = defaultdict(list)

	for line in open(file, 'r'):
		if "sasl login authentication failed" in line.lower():
			# try to extract the ip address from the log line
			try:
				ip = re.search('(?:[0-9]{1,3}\.){3}[0-9]{1,3}', line).group(0)
			except AttributeError:
				ip = ''

			if ip:
				# now get the timestamp from the log line
				try:
					timestamp = re.search('^[A-Z][a-z]{2} [ 0123][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2}', line).group(0)
				except AttributeError:
					timestamp = ''

				if timestamp:
					failedLogins[ip].append(timestamp)
	return failedLogins

# --------------------------------------------------------------
def printList(theList):
	"""output a formatted list of logged ip addresses, attempt timestamps and block state"""
	print("IP\t\t\tfailed Logins\t\tlatest\t\t\tstate")
	output 			= []
	routingTable 	= getRoutingTable()

	if len(theList) > 0:	
		# remove routes that are not host routes
		for line in routingTable:
			if not "!H" in line:
				routingTable.remove(line)

		# check the list of "offending" IPs against the routing table
		# and mark them as open/blocked 
		for ip in theList.keys():
			state = None
			for line in routingTable:
				if ip in line:
					state = color.OKGREEN + "[blocked]"

			if state == None:
				state = "[open]"
				state = color.FAIL + state if (len(theList[ip]) > banThreshold) else color.WARNING + state

			state += color.ENDC

			output.append((ip, len(theList[ip]), theList[ip][-1], state))

		# sort by last time of last failed login attempt
		output.sort(key=lambda tup: tup[2], reverse=True)

		for line in output:
			print("{:20}\t{:5}\t\t\t{:20}\t{:10}".format(*line))
	else:
		print("(no unsuccessful connection attempts found in log file)")

# --------------------------------------------------------------
def blackhole(op, ip):
	""" 
	take an ip address and create a blackhole route
	then store that info in a database so this route can be removed again after some time to prevent cluttering the routing table
	"""

	class ArgumentError(Exception):
		"""define some custom exceptions"""
		pass
	
	if re.match('(?:[0-9]{1,3}\.){3}[0-9]{1,3}', ip) == None:
		raise ArgumentError("Specified ip address looks not right: " + ip)

	if not ( op == "add" or op == "del"):
		raise ArgumentError("Operation can only be 'add' or 'del', not: " + op)

	try:
		subprocess.check_call(["/usr/sbin/route", op, "-host", ip, "reject" ])
		return True
	except subprocess.CalledProcessError as e:
		print ("Error adding host route. Subprocess exited with returncode " +  str(e.returncode))
		return False
	except Exception as e:
		print (str(e))
		return False

# --------------------------------------------------------------
def getRoutingTable():
	try:
		routingTable = subprocess.check_output(["/usr/sbin/route", "-n"], stderr=subprocess.STDOUT)
		return routingTable.decode("utf-8").split("\n")[2:]
	except subprocess.CalledProcessError:
		print (subprocess.output)
		sys.exit(1)
	except Exception as e:
		print (str(e))
		sys.exit(1)
	

# --------------------------------------------------------------
def dbstore(blocklist, mode="cf"):
	"""write the blocklist dictionary to a db file"""
	if len(blocklist) > 0: # no need to store an empty file
		try:
			with dbm.gnu.open(dbfile, mode, 0o600) as db:
				for ip, date in blocklist.items():
					db[ip] = date
		except (dbm.gnu.error, KeyError) as e:
			print (str(e))
			return False
	return True


# --------------------------------------------------------------
def dbread(file):
	"""populate a dictionary (= blocklist) from a db file"""
	blocklist = {}
	try:
		with dbm.gnu.open(file, "r") as db:
			k = db.firstkey()
			while k != None:
				blocklist[k.decode("utf-8")] = db[k].decode("utf-8")
				k = db.nextkey(k)
	except Exception as e:
		print(str(e))
	
	# note: dicts can't be sorted; we'd need to create a sorted list of tupels
	return blocklist
# --------------------------------------------------------------
def showDbContents(dbfile):
	"""print the blocklist from the database in ordered by time descending"""
	blocklist = dbread(dbfile)
	if len(blocklist) == 0:
		print("DB file is empty.")
	else:
#		blocklist = sorted(blocklist.items(), key=lambda tup: tup[1], reverse=True)
		blocklist = sorted(blocklist.items(), key=lambda tup: time.mktime(time.strptime(tup[1], "%Y %b %d %H:%M:%S")), reverse=True)
		for ip, date in blocklist:
			print("{:15} blocked on {}".format(ip, date))


# --------------------------------------------------------------
# remove old entries from db file and delete the corresponding routes;
#
# no need to check if there are still connection attempts from those ips,
# since they won't show up in the logfile anyway as long as they're blocked

def expire(dbfile):
	blocklist 	= dbread(dbfile)
	now			= datetime.now()
	if len(blocklist) == 0:
		print("DB file is empty.")
	else:
		for ip, date in blocklist.copy().items():  # need to work on a copy to prevent "RuntimeError: dictionary changed size during iteration"
			then = datetime.strptime(date, "%Y %b %d %H:%M:%S")
			if (now - then > timedelta(days=banPeriod)):
				# remove route  and db item
				if verbose: print("Unblocking IP " + ip)
				blackhole("del", ip)
				del blocklist[ip] 
	dbstore(blocklist, mode="nf")
# --------------------------------------------------------------
# block offending ips if necessary; store them in db
def block():
	class RouteExistsError(Exception): pass	

	routingTable	= getRoutingTable()
	blocklist 		= dbread(dbfile)
	
	# add ips from logfile to our blocklist (if one was specified)...
	for ip, attempts in getFailedLogins(source).items():
		if ip in blocklist: continue 	# ignore ip addresses from the log file if they are already in our blockist
		if len(attempts) >= banThreshold:
			blocklist[ip] = datetime.strftime(datetime.now(),"%Y %b %d %H:%M:%S")
		#	blocklist[ip] = datetime.strftime(datetime.now(),"%Y ") + str(attempts[-1])
		else:
			if verbose: print("{} number of connection attempts below threshold ({}<{}). not blocking.".format(ip, len(attempts), banThreshold))

	# ... then iterate over the ips in the resulting blocklist and create routes
	for ip in blocklist:
		try:
			for route in routingTable:
				if ip in route:
					raise RouteExistsError(ip)
			if verbose: print("Blocking IP (blocklist)" + ip)
			blackhole("add",ip)
		except RouteExistsError as e:
			if verbose: print(str(e) + " is already blackholed")

	# finally save the block list in its current state
	dbstore(blocklist)

# --------------------------------------------------------------
def main(argv):

	parser = argparse.ArgumentParser(description="Blackhole IP addresses from unwanted SMTP connections.")
#	parser.add_argument('--debug', '-d', action='store_true', default=False)
	parser.add_argument('--print', '-p', action='store_true', default=False, help='Analyse logfile and show a list of offending IPs and their state. Also shows DB contents.')
	parser.add_argument('--block', '-b', action='store_true', default=False, help='Analyse logfile and add blackhole routes for offending IPs if needed.')
	parser.add_argument('--expire', '-e', action='store_true', default=False, help='Removes old blackhole routes and corresponding db entries.')
	parser.add_argument('--quiet', '-q', action='store_true', default=False, help='Suppress most informational output.')
	parser.add_argument('--verbose', '-v', action='store_true', default=False, help='Increase verbosity.')
	args = parser.parse_args()

	if not (args.print or args.block or args.expire):
		parser.print_usage()
		sys.exit(1)

	global color
	color = mycolors()

	if args.quiet:
		global silentMode
		silentMode = True

	if args.verbose:
		global verbose
		verbose = True

	if args.expire:
		expire(dbfile)

	if args.print:
		print("Analyzing logfile:")
		printList(getFailedLogins(source))
		print("\nContents of database file:")
		showDbContents(dbfile)
	
	if args.block:
		block()

#	if args.debug:
#		printList(getFailedLogins(source))

if __name__ == "__main__":
    main(sys.argv[1:])
