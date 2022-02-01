NefFilter-Queue FireWall (nfqfw)

Implemented using Linux libnetfilterqueue in user-space

Written by Bill Brassfield ( https://github.com/brassb )

January 2022



To build (on Linux):

1. Be sure 'gcc' and 'make' are installed on the system.

2. Make sure the libnetfilter_queue C header files and
   libraries are installed.

3. Make sure the OpenSSL development C header files and
   libraries are installed.

4. In this src directory, run:

     make

   Alternatively, you may run:

     gcc -o nfqfw nfqfw.c -lnetfilter_queue -lcrypto

If all went well, you should have a new executable:

  nfqfw

  (This must be run as root, and with the correct command-line options
  for your environment.)


DISCLAIMER:

This software is provided free and open-source, as-is, and comes with no
warranty or assumption of any liability by the author(s) of the software.
Read the GNU GPL (General Public License) for details on how this works.

This is NOT production software.  DO NOT, under any circumstances, rely on
this software to provide you with any form of network or host level security.
You may inadvertently (and quite easily) lock yourself out of important
Linux server hosts if nfqfw and/or its accompanying iptables firewall rules
are not set up properly.  Additionally, there is a good possibility that it
may not provide the desired level of protection against rogue actors who wish
to penetrate any defenses built from this software.

This software is for teaching, learning, and experimental computer-lab-use
ONLY.  This software is the equivalant of a child's toy, made out of easy-
to-break plastic, and just strong enough to survive 5 minutes after the birthday
gift is unwrapped before it breaks.  This is not heavy-duty, super-robust,
enterprise-grade 6-figure software made out of bullet-proof Uranium tank
armor.  It may segfault and core-dump, it may crash your Linux system, it
may render mission-critical systems unreachable to you and your admins, and
it may give you a false sense of security but be weak enough to provide an
easy back-door for hackers to break into your systems.

YOU HAVE BEEN WARNED.  USE THIS SOFTWARE AT YOUR OWN RISK.

But at the same time, please have fun with it.  And hopefully, you will
learn something and be inspired to write your own user-space NetFilter-Queue
IP-packet processors for Linux.
