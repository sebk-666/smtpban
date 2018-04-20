**smtpban.py**

Simple Python script that scans a local `maillog` file for failed connection attempts
from remote hosts and then blocks any IP address with more than a specified number of failed attempts.

Blocking is done by setting up a "black hole" route for this IP address, i.e. `route add -host <IP> reject`.

Tested on Linux only.

I wrote this to improve my Python skills and because I found that `fail2ban` comes with too much overhead in this case.