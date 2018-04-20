# smtpban.py

## Introduction

Simple Python script that scans a local `maillog` file for failed connection attempts
from remote hosts and then blocks any IP address with more than a specified number of failed attempts.

Blocking is done by setting up a "black hole" route for this IP address, i.e. `route add -host <IP> reject`.

The currently blackholed IP addresses are stored in a database file, so the "blackhole-routes" can 
easily be set up again after a system reboot.

An expiry-mechanism allows to remove IP addresses from the "block list" after a configurable number of days
so the routing table will not be cluttered up on a long-running system.

Tested only on my personal Linux server running Postfix.

I wrote this to improve my Python skills and because I found that `fail2ban` comes with too much overhead in this case.

Feedback welcome.


## Usage
```
# ./smtpban.py -h
usage: smtpban.py [-h] [--print] [--block] [--expire] [--quiet] [--verbose]

Blackhole IP addresses from unwanted SMTP connections.

optional arguments:
  -h, --help     show this help message and exit
  --print, -p    Analyse logfile and show a list of offending IPs and their
                 state. Also shows DB contents.
  --block, -b    Analyse logfile and add blackhole routes for offending IPs if
                 needed.
  --expire, -e   Removes old blackhole routes and corresponding db entries.
  --quiet, -q    Suppress most informational output.
  --verbose, -v  Increase verbosity.
```
