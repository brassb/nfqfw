The nfqfw program must be run as root, so that it may access the data
structures in the NFQUEUE target of Linux's NetFilter (commonly managed by
IpTables).  Ideally, the program should be run as a daemon, but at the
moment it's not yet written to self-daemonize.  You will therefore need to
run it from a wrapper program which can daemonize, or alternatively, you can
run it from inside a "screen" or "tmux" session.

  sudo su -

  screen

  ./nfqfw --verbose=0 --queue-number=0 \
     --hmac-secret-filename=hmac_secret.txt \
     --hmac-length-in-bytes=16

This program must be run on both the client host and the server host. 
Additionally, in order for proper HMAC-based authentication to be
successful, both the client and the server must possess exactly the same
contents in their hmac_secret.txt file (or whatever you choose to name the
file).  Also, the hmac length in bytes (recommended to be anywhere between
16 and 32 bytes, inclusively) must be the same on both client and server.

The command invocation shown above is actually using default values.  The
NFQUEUE queue-number can be anything from 0 to 65535, inclusively.  The path
to the HMAC secret filename can be up to 255 characters in length.  The HMAC
length in bytes actually can be less than 16 (can be as low as 1 byte), but
such a small HMAC would be insecure and not recommended.  Verbosity level
can be 0, 1, or 2.  Verbosity level 0 is "quiet", so there shouldn't be any
output from nfqfw to STDOUT or to STDERR unless something really goes wrong. 
Verbosity level 1 is typically just a few lines of output to STDOUT per IP
packet processed.  Verbosity level 2 is quite verbose, with typically between
60 and 100 lines of output to STDOUT per IP packet processed.

In order for nfqfw to have any packets to process, some firewall rules need
to be in place.  At a bare minimum, firewall rules such as the following
should be in place to intercept both inbound and outbound traffic:

  iptables -A INPUT  -s <remote-ip-address>/32 -j NFQUEUE --queue-num 0
  iptables -A OUTPUT -d <remote-ip-address>/32 -j NFQUEUE --queue-num 0

    (NOTE: These iptables command must be run as root, or with sudo.)

The example iptables commands shown above are actually more appropriate for
use on the client host, so that it will go through NFQUEUE (queue 0) any
time it wants to send/receive IP traffic to/from the server host, whose IP
address would be filled in as the remote-ip-address.  On the server end, it
may be desirable to lock down traffic very tightly and require nfqfw to
process all ICMP packets and all packets coming into the SSH port, for example:

  iptables -A INPUT  -p icmp -j NFQUEUE --queue-num 0
  iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 0

  iptables -A INPUT  -p tcp -m tcp --dport 22 -j NFQUEUE --queue-num 0
  iptables -A OUTPUT -p tcp -m tcp --sport 22 -j NFQUEUE --queue-num 0

It's important to note that you can easily lock yourself out of the server
(i.e., be unable to ssh into it) if you set up the iptables rules incorrectly
and/or run nfqfw incorrectly (or not at all), so take great care in setting up
nfqfw.  It's highly recommended that you have out-of-band access to the console
of your server before locking down its ssh port using nfqfw.

Another thing which should be mentioned is that by default, nfqfw runs in what
could be called "lan mode".  What this means is that a bare minimum number of
header bytes are "zeroed out" for calculation of the HMAC, mainly just the IP
checksum and the ICMP, TCP, or UDP checksum.  In order for the HMAC to compute
to the same value across the Internet (through routers and possibly through NAT),
the nfqfw program needs to be run with the "--wanmode" command-line switch.  This
will zero-out additional header fields before the HMAC is computed.  This is
necessary because fields such as source and destination IP address, source and
destination port, type-of-service, and time-to-live are not guaranteed to remain
constant.  Using "--wanmode" ignores changes in these fields.  It's important to
note that both client and server instance of nfqfw must be in the same mode (both
in the default "lan mode", or both in "--wanmode").  If only one is in "--wanmode",
the HMAC calculations will be different, and packet authentications (and therefore
connectivity between client and server) will fail.

Another very important thing to configure, using IPTables commands, is the MSS
(Maximum Segment Size), to ensure that the HMAC-appended packets (appended within
the payload) may still traverse the network between client and server (and back)
without exceeding the minimum MTU along the way.  This number is typically 1500,
but it can be smaller in some situations, especially if a VPN is involved.  Here
are a couple of additional firewall rules which can be used to force TCP traffic
to use smaller TCP payloads per packet (and thus smaller IP packet sizes), so that
fragmentation of packets can be avoided:

  Configure something like this on the client host:

    iptables -t mangle -A INPUT  -s <remote-ip-address>/32 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400
    iptables -t mangle -A OUTPUT -d <remote-ip-address>/32 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400

  Configure something like this on the server host:

    iptables -t mangle -A INPUT  -p tcp -m tcp --dport 22 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400
    iptables -t mangle -A OUTPUT -p tcp -m tcp --sport 22 --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400


DISCLAIMER:

This is NOT production-quality code (at least not yet, as of January 31, 2022).  Use
this code AT YOUR OWN RISK.  I shall NOT be held responsible for any damages caused
by the use or misuse of this software.  At this time, it is, at best, only a "lab
experiment", and something to play with as a teaching and/or learning tool.  Use of
this software can easily lock you out of any host onto which you install and run it
(with the iptables rules also in place).  Also, this software has NOT been through
any "security audit" whatsoever, so the vulnerabilities of it to aggressive, targeted
attacks are unknown.

