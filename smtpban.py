#!/usr/bin/env python3
""" Scan mail log for failed SMTP login attempts
    and blackhole the offending IP addresses.
"""
__version__ = '0.1'
__author__ = 'Sebastian Kaps (sebk-666)'

import argparse
from collections import defaultdict
from datetime import datetime, timedelta
import dbm.gnu
import ipaddress
from pathlib import Path
import re
import subprocess
import sys
import time

# path to the mail log file
SOURCE_LOG = "/var/log/maillog"

# path to the programs database file (the file will be created automatically)
DB_FILE = "/root/smtpban.db"

# blackhole ip after this many failed logins
BAN_THRESHOLD = 5

# expire the blackhole route after this many days
BAN_DAYS = 7

# if true, suppress all output
SILENT = False

# if true, log blocked/unblocked IPs to stdout
VERBOSE = False

# list of IPv4/IPv6 addresses/networks to prevent from getting blocked
WHITELIST = ['192.168.0.0/16']


class MyColors:
    """define some constants for colored output on the shell"""
    # pylint: disable=C0103
    HEADER = ''
    OKBLUE = ''
    OKGREEN = ''
    WARNING = ''
    FAIL = ''
    ENDC = ''
    BOLD = ''
    UNDERLINE = ''

    def __init__(self):
        """
        initialize the class attributes to only use colour escape sequences
        when on a tty
        """
        if sys.stdout.isatty():
            self.HEADER = '\033[95m'
            self.OKBLUE = '\033[94m'
            self.OKGREEN = '\033[92m'
            self.WARNING = '\033[93m'
            self.FAIL = '\033[91m'
            self.ENDC = '\033[0m'
            self.BOLD = '\033[1m'
            self.UNDERLINE = '\033[4m'


def print(*args, **kwargs):  # pylint: disable=redefined-builtin
    """Override the print function to suppress output in silent mode."""
    if not SILENT:
        return __builtins__.print(*args, **kwargs)
    return None


def getfailed_logins(file):
    """
    return a dictionary with a list of (dates of...) failed login
    attempts (= values) for each ip (= keys) from the mail log file
    """
    failed_logins = defaultdict(list)

    for line in open(file, 'r'):
        if "sasl login authentication failed" in line.lower():
            # try to extract the ip address from the log line
            try:
                ip_addr = re.search(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', line)\
                            .group(0)
            except AttributeError:
                ip_addr = ''

            if ip_addr:
                # now get the timestamp from the log line
                try:
                    timestamp = re.search(r'^[A-Z][a-z]{2} [ 0123][0-9] '
                                          r'[0-9]{2}:[0-9]{2}:[0-9]{2}', line)\
                                          .group(0)
                except AttributeError:
                    timestamp = ''

                if timestamp:
                    failed_logins[ip_addr].append(timestamp)
    return failed_logins


def print_list(the_list):
    """
    output a formatted list of logged ip addresses,
    attempt timestamps and block state
    """
    print("IP\t\t\tfailed Logins\t\tlatest\t\t\tstate")
    output = list()
    routing_table = get_routingtable()

    if the_list:
        # remove routes that are not host routes
        for line in routing_table:
            if "!H" not in line:
                routing_table.remove(line)

        # check the list of "offending" IPs against the routing table
        # and mark them as open/blocked
        for ip_addr in the_list.keys():
            state = None
            for line in routing_table:
                if ip_addr in line:
                    state = MyColors.OKGREEN + "[blocked]"

            if state is None:
                state = "[open]"
                if len(the_list[ip_addr]) > BAN_THRESHOLD:
                    state = MyColors.FAIL + state
                else:
                    state = MyColors.WARNING + state
            state += MyColors.ENDC

            output.append((ip_addr, len(the_list[ip_addr]),
                           the_list[ip_addr][-1], state))

        # sort by last time of last failed login attempt
        output.sort(key=lambda tup: tup[2], reverse=True)

        for line in output:
            print("{:20}\t{:5}\t\t\t{:20}\t{:10}".format(*line))
    else:
        print("(no unsuccessful connection attempts found in log file)")


def blackhole(oper, ip_addr):
    """
    take an ip address and create a blackhole route for it,
    then store that info in a database so this route can be removed again
    after some time to prevent cluttering the routing table
    """

    class ArgumentError(Exception):
        """define a custom exception"""
        pass

    print("Blackhole: {} : {}".format(oper, ip_addr))
    return True

    if re.match(r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}', ip_addr) is None:
        raise ArgumentError("Specified ip address does not look right: "
                            + ip_addr)

    if oper not in ['add', 'del']:
        raise ArgumentError("Operation can only be 'add' or 'del', not: "
                            + oper)

    try:
        subprocess.check_call(["/usr/sbin/route",
                               oper, "-host", ip_addr, "reject"])
        return True
    except subprocess.CalledProcessError as err:
        print("Error adding host route. Subprocess exited with returncode "
              + str(err.returncode))
        return False


def get_routingtable():
    """Return the current routing table"""
    try:
        routing_table = subprocess.check_output(["/usr/sbin/route", "-n"],
                                                stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        print(subprocess.getoutput)
        sys.exit(1)
    return routing_table.decode("utf-8").split("\n")[2:]


def db_store(blocklist, mode="cf"):
    """Write the blocklist dictionary to a GNU DB file."""
    if blocklist:   # no need to store an empty file
        try:
            # pylint: disable=C0103
            with dbm.gnu.open(DB_FILE, mode, 0o600) as db:
                for ip, date in blocklist.items():
                    db[ip] = date
        except (dbm.gnu.error, KeyError) as err:
            print(str(err))
            return False
    return True


def db_read(file):
    """Read the program's GNU DB file and populate a dictionary (aka blocklist)
       with its contents.
    """
    blocklist = {}
    if not Path(file).is_file():
        print("DB file does not exist.")
    else:
        try:
            # pylint: disable=C0103
            with dbm.gnu.open(file, "r") as db:
                k = db.firstkey()
                while k is not None:
                    blocklist[k.decode("utf-8")] = db[k].decode("utf-8")
                    k = db.nextkey(k)
        except IOError as err:
            print("Error reading DB file:", err)

    # note: dicts can't be sorted; we'd need to create a sorted list of tupels
    return blocklist


def show_db_contents(db_file):
    """print the blocklist from the database in ordered by time descending"""
    blocklist = db_read(db_file)
    if not blocklist:
        print("DB file is empty.")
    else:
        blocklist = sorted(blocklist.items(),
                           key=lambda tup: time.mktime(time.strptime(tup[1],
                                                       "%Y %b %d %H:%M:%S")),
                           reverse=True)

        for ip_addr, date in blocklist:
            print("{:15} blocked on {}".format(ip_addr, date))


def expire(db_file):
    """Remove old entries from db file and delete the corresponding routes."""

    blocklist = db_read(db_file)
    now = datetime.now()

    if not blocklist:
        print("DB file is empty.")
    else:
        for ip_addr, date in blocklist.copy().items():
            # need to work on a copy of the blocklist to prevent
            # "RuntimeError: dictionary changed size during iteration"
            then = datetime.strptime(date, "%Y %b %d %H:%M:%S")
            if now - then > timedelta(days=BAN_DAYS):
                # remove route  and db item
                if VERBOSE:
                    print("Unblocking IP " + ip_addr)
                blackhole("del", ip_addr)
                del blocklist[ip_addr]
    db_store(blocklist, mode="nf")


def block():
    """Block offending ips if necessary; store them in db."""

    class RouteExistsError(Exception):
        """Exception for when trying to insert a route that already exists."""
        pass

    routing_table = get_routingtable()
    blocklist = db_read(DB_FILE)

    # process the WHITELIST entries
    whitelisted = []
    for entry in WHITELIST:
        if '/' in entry:
            # assume it's a network
            whitelisted.append(ipaddress.ip_network(entry))
        else:
            # single IP address
            whitelisted.append(ipaddress.ip_address(entry))

    # add IPs from logfile to our blocklist
    for ip_addr, attempts in getfailed_logins(SOURCE_LOG).items():
        # ignore addresses configured in WHITELIST
        skip = False
        ip_obj = ipaddress.ip_address(ip_addr)
        for item in whitelisted:
            if isinstance(item, (ipaddress.IPv4Address,
                                 ipaddress.IPv6Address)):
                if ip_obj == item:
                    print("IP from Logfile ({}) is whitelisted".format(ip_obj))
                    skip = True
                    break

            elif isinstance(item, (ipaddress.IPv4Network,
                                   ipaddress.IPv6Network)):
                if ip_obj in item:
                    print("IP from Logfile ({}) is whitelisted via network {}"
                          .format(ip_obj, item))
                    skip = True
                    break

        # we found a whitelisted address; skip processing it
        if skip:
            continue

        print("Block: ", ip_addr)
        if ip_addr in blocklist:
            # ignore ip addresses from log file if already in our blockist
            continue

        if len(attempts) >= BAN_THRESHOLD:
            blocklist[ip_addr] = datetime.strftime(datetime.now(),
                                                   "%Y %b %d %H:%M:%S")
        else:
            if VERBOSE:
                print("{} number of connection attempts below threshold"
                      .format(ip_addr),
                      "({}<{}). Not blocking."
                      .format(len(attempts), BAN_THRESHOLD))

    # then iterate over the IPs in the resulting blocklist and create routes
    for ip_addr in blocklist:
        try:
            for route in routing_table:
                if ip_addr in route:
                    raise RouteExistsError(ip_addr)
            if VERBOSE:
                print("Blocking IP (blocklist)" + ip_addr)
            blackhole("add", ip_addr)
        except RouteExistsError as err:
            if VERBOSE:
                print(str(err) + " is already blackholed")
    # finally save the block list in its current state
    db_store(blocklist)


def main(argv):
    """Jepp. You guessed it: main()"""

    parser = argparse.ArgumentParser(description="Blackhole IP addresses from\
                                                 unwanted SMTP connections.")

    parser.add_argument('--print', '-p',
                        action='store_true',
                        default=False,
                        help='Analyse logfile and show a list of offending IPs\
                             and their state. Also shows DB contents.')

    parser.add_argument('--block', '-b',
                        action='store_true',
                        default=False,
                        help='Analyse logfile and add blackhole routes \
                             for offending IPs if needed.')

    parser.add_argument('--expire', '-e',
                        action='store_true',
                        default=False,
                        help='Removes old blackhole routes and corresponding \
                             db entries.')

    parser.add_argument('--quiet', '-q',
                        action='store_true',
                        default=False,
                        help='Suppress most informational output.')

    parser.add_argument('--verbose', '-v',
                        action='store_true',
                        default=False,
                        help='Increase verbosity.')

    args = parser.parse_args()

    if not (args.print or
            args.block or
            args.expire):
        parser.print_usage()
        sys.exit(1)

    if args.quiet:
        global SILENT
        SILENT = True

    if args.verbose:
        global VERBOSE
        VERBOSE = True

    if args.expire:
        expire(DB_FILE)

    if args.print:
        print("Analyzing logfile:")
        print_list(getfailed_logins(SOURCE_LOG))
        print("\nContents of database file:")
        show_db_contents(DB_FILE)

    if args.block:
        block()


if __name__ == "__main__":
    main(sys.argv[1:])
