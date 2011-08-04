#!/bin/sh
#
# netsane (1.1) - a load-balancing, multipath iproute2 script.
#
# This script is heavily based upon the advanced routing
# howto available at: http://lartc.org/ as well as 
# Christoph Simon's Nano-Howto available at:
# http://www.ssi.bg/~ja/nano.txt
#
# Copyright (c) 2003 Roger Gregory <rtgregory@gmail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# 3. The name of the author may not be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
# THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# WHERE IS THE CONF?
WHERE_IS_NETSANE_CONF_LOCATED="/etc/netsane/netsane.conf"

# Misc variables
NULLS=$(grep -vE '^[[:space:]]*(#|$)' /etc/netsane/blackhole)


## Begin
source $WHERE_IS_NETSANE_CONF_LOCATED

flush_netsane() {
	
	echo "[netsane] flushing .."
	cp -f /etc/iproute2/rt_tables_SANE /etc/iproute2/rt_tables
	
	$IP route del $IP1_NET dev $IF1 src $IP1 table $IF1_NAME 2> /dev/null
	$IP route del default 
	$IP route del $IP2_NET dev $IF2 src $IP2 table $IF2_NAME 2> /dev/null
					
	$IP route add default via $FAIL_SAFE_DEFAULT_GATEWAY || (echo "[netsane] Problem adding default gateway back")
	
	# remove any blackholed routes
	if [ $NULLS ]; then
		for nulled in $NULLS; do
			$IP rule delete blackhole from $nulled
		done
	fi

	echo "[netsane] Flush complete .. routing table output follows"
	echo "--------------------------------------------------------"
	$IP route sh
	echo "--------------------------------------------------------"
}

drop_ip1() {
	$IP route del default 
	$IP route add default via $IP2_GW
} 

drop_ip2() {
	$IP route del default
	$IP route add default via $IP1_GW
}

bad_user() {
	
	echo "[netsane] BAD USER!"
	echo "[netsane] Failed to find clean copy of rt_tables!"
	echo "[netsane] Let's hope we have a good copy.."
	cp -f /etc/iproute2/rt_tables_OLD /etc/iproute2/rt_tables || really_bad_user
	echo "[netsane] Copied rt_tables_OLD to rt_tables"
}

really_bad_user() {
	
	echo "[netsane] Ugh!"
	echo "[netsane] Unable to find any known-good rt_tables"
	echo "[netsane] I have no choice but to load failsafe"
	echo "[netsane] ..."
	cp -f /etc/netsane/rt_tables_failsafe /etc/iproute2/rt_tables
	exit 1
}

grok_interface() {

	if [ ! -z "`$IFCFG $FACE 2>/dev/null | grep UP`" ];
		then
			echo "[netsane] interface $FACE up"
		else
			echo "[netsane] interface $FACE -not- up (bailing)"
			exit 1
	fi
}

init_netsane() {

	echo "[netsane] initializing .."

	case "$ROUTER" in
		equalize)
			ROUT="add default equalize"
			echo "[netsane] Using 'equalize' - if this errors switch ROUTER to 'standard' in netsane.conf"
		;;

		standard)
			ROUT="add default scope global"
		;;

		split)
			ROUT="add default $FAIL_SAFE_DEFAULT_GATEWAY"
		;;

		*)
		 	ROUT="add default scope global"
		;;
	
	esac	
	
	# grok interface IP's
	for FACE in $IF1 $IF2; do
		if [ "$FACE" == "AUTO" ]; then
			groke_interface
		fi
	done

	# Check to ensure we have a clean rt_tables
	if [ -e /etc/iproute2/rt_tables_OLD ]; then
		echo "[netsane] Good, clean rt_tables present .."
	else
		echo "[netsane] No backup rt_tables present, I'll make one .."
		cp -f /etc/iproute2/rt_tables /etc/iproute2/rt_tables_OLD
	fi
	
	# Backup interesting files
	cp -f /etc/iproute2/rt_tables /etc/iproute2/rt_tables_1

	# Create routing table names for easy use
	if [[ ! -n `grep "36 $IF1_NAME" /etc/iproute2/rt_tables` ]]; then
		echo 36 $IF1_NAME >> /etc/iproute2/rt_tables || (echo "[netsane] ERROR: Problem writing to /etc/iproute2/rt_tables." && exit 1)
	fi

	if [[ ! -n `grep "37 $IF2_NAME" /etc/iproute2/rt_tables` ]]; then
		echo 37 $IF2_NAME >> /etc/iproute2/rt_tables || (echo "[netsane] ERROR: Problem writing to /etc/iproute2/rt_tables." && exit 1)
	fi

	# Ensure older default routes are not hanging around
	DEFAULT=`$IP route show | awk '{if (/default/) {print $3}}'`

	if [ "$DEFAULT" == "" ]; then 
			echo "[netsane] NO default gateway determined .. good"
	else
			echo "[netsane] Noted default gateway of $DEFAULT .. deleting"
			$IP route delete default
	fi

	# Create proper routes for delivering packets back out
	# the same provider they arrive from
	
	$IP route add $IP1_NET dev $IF1 src $IP1 table $IF1_NAME 2> /dev/null
	$IP route add default via $IP1_GW table $IF1_NAME 2> /dev/null
	
	$IP route add $IP2_NET dev $IF2 src $IP2 table $IF2_NAME 2> /dev/null
	$IP route add default via $IP2_GW table $IF2_NAME 2> /dev/null

	# Create the main routing table
	$IP route add $IP1_NET dev $IF1 src $IP1 2> /dev/null
	$IP route add $IP2_NET dev $IF2 src $IP2 2> /dev/null

	# Create routing rules
	$IP rule add from $IP1 table $IF1_NAME 2> /dev/null
	$IP rule add from $IP2 table $IF2_NAME 2> /dev/null

	# Add some logic to gracefully fail should a given interface fail. Cheers
	# to Christoph Simon's documentation.
	$IP route append prohibit default table $IF1_NAME metric 1 proto static 2> /dev/null
	$IP route append prohibit default table $IF2_NAME metric 1 proto static 2> /dev/null
	
	# We want to load balance out these two
	# routing tables
	echo "[netsane] attempting to add multipath.."
	$IP route $ROUT nexthop via $IP1_GW dev $IF1 weight $IP1_WEIGHT \
		nexthop via $IP2_GW dev $IF2 weight $IP2_WEIGHT 2> /dev/null
	
	# Check for buggy iproute2 magic
	if [ `ip route show | awk '{if (/nexthop/) {print $8}}' | grep dead` ]; then

		BADGW=`ip route show | grep dead | awk '{if (/nexthop/) {print $3}}'`
			
		echo ""
		echo "[netsane] ** WARNING **"
		echo ""
		echo "[netsane] Detected iproute bug!"
		echo "[netsane] See http://marc.theaimsgroup.com/?l=lartc&m=100885677229167&w=2"
		echo "[netsane] $BADGW listed as 'dead'"
		echo "[netsane] Attempting workaround .."
		
		$IP route delete default
		
		case "$BADGW" in
				
			"$IP1_GW")
				 $IP route $ROUT nexthop via $IP1_GW dev $IF1 weight $IP1_WEIGHT \
				 nexthop via $IP1_GW dev $IF1 weight $IP1_WEIGHT \
				 nexthop via $IP2_GW dev $IF2 weight $IP2_WEIGHT 2> /dev/null
				 echo "[netsane] Duplicated $IP1_GW .."
			;;

			"$IP2_GW")
				 $IP route $ROUT nexthop via $IP1_GW dev $IF1 weight $IP1_WEIGHT \
				 nexthop via $IP2_GW dev $IF2 weight $IP2_WEIGHT \
				 nexthop via $IP2_GW dev $IF2 weight $IP2_WEIGHT 2> /dev/null
				 echo "[netsane] Duplicated $IP2_GW .."
			;;

			*)
				echo "[netsane] Eeek! Can't figure out interface gateways!"
				echo "[netsane] Bailing!"
				exit 1
			;;
			
		esac
					 
	fi
	
	# Add any defined blackhole routes
	if [ "$NULLS" ]; then
		for nulled in $NULLS; do
			echo "[netsane] blackhole routing $nulled .."
			$IP rule add blackhole from $nulled
		done
	fi

	# Add specific routing destinations
	for ip1_route in $IP1_ALWAYS; do
		echo "[netsane] routing $ip1_route via $IF1"
		$IP route add $ip1_route nexthop via $IP1_GW dev $IF1 weight 1 2> /dev/null
	done

	for ip2_route in $IP2_ALWAYS; do
		echo "[netsane] routing $ip2_route via $IF2"
		$IP route add $ip2_route nexthop via $IP2_GW dev $IF2 weight 1 2> /dev/null
	done

	# Use iptables to mark specific packet flows to ensure they
	# utilize specific routes
	
	if [[ "$IP1_PORTS" ]]; then
		
		if [ -e /lib/modules/`/bin/uname -r`/kernel/net/ipv4/netfilter/iptable_mangle ]; then
			/sbin/modprobe/iptable_mangle 2> /dev/null
		else
			echo "[netsane] No iptable_mangle modules detected .. "
		fi
		
		for ports in $IP1_PORTS; do
			$IPT -I PREROUTING -i $IF1 -t mangle -p tcp --dport $ports -j MARK --set-mark 50
			$IPT -I PREROUTING -i $IF1 -t mangle -p udp --dport $ports -j MARK --set-mark 50
			echo "[netsane] routing traffice to port $ports out $IF1_NAME"
		done
		
		if [[ ! -n `grep 38 /etc/iproute2/rt_tables` ]]; then
			echo "38 $IF1.out" >> /etc/iproute2/rt_tables
		fi
		
		$IP rule add fwmark 50 table $IF1.out 2> /dev/null
		$IP add default via $IF1_GW dev $IF1 table $IF1.out
		
	fi

	if [[ "$IP2_PORTS" ]]; then

		if [ -e /lib/modules/`/bin/uname -r`/kernel/net/ipv4/netfilter/iptable_mangle ]; then
			/sbin/modprobe/iptable_mangle 2> /dev/null
		else
			echo "[netsane] No iptable_mangle modules detected .. "
		fi

		for ports in $IP2_PORTS; do
			$IPT -I PREROUTING -i $IF2 -t mangle -p tcp --dport $ports -j MARK --set-mark 51
			$IPT -I PREROUTING -i $IF2 -t mangle -p udp --dport $ports -j MARK --set-mark 51
			echo "[netsane] Marking packets destined for port $ports via iptables .."
		done

		if [[ ! -n `grep 39 /etc/iproute2/rt_tables` ]]; then
			echo "39 $IF1.out" >> /etc/iproute2/rt_tables
		fi
		
		$IP rule add fwmark 51 table $IF1_NAME 2> /dev/null
		$IP add nexthop via $IF2_GW dev $IF2 table $IF2.out
	fi
	
	echo "[netsane] All done .. "
}

usage(){
	cat<<EOF
Netsane accepts the following options:

	-f|stop    ............... (flush) remove multiroutes
	init|start ............... (init) start netsane
	restart    ............... (restart) restart netsane
	-dip1      ............... (drop ip1gw) remove IP1 gateway
	-dip2      ............... (drop ip2gw) remove IP2 gateway
	-h|help    ............... (help) print usage

EOF
	exit 1
}

# Parse start options
case "$1" in
	
	-f|stop)
		flush_netsane
	;;

	init|start)
		init_netsane
	;;

	restart)
		flush_netsane
		init_netsane
	;;

	-dip1|drop_ip1_gw)
		drop_ip1
	;;

	 -dip2|drop_ip2_gw)
	 	drop_ip2
	;;

	-h|help)
		usage
	;;
		
	*)
		init_netsane
	;;

esac
