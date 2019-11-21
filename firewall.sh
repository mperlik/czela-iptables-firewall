#!/bin/sh

###########################################################
##     F I R E W A L L    #################################
###########################################################

IPTABLES="`which iptables`"
#INDEV="eth0.4055"
INDEV="eth0.4015"
INDEV1="eth0.4005"
OUTDEV="eth0.4001"

if [ "$1" == "start" ] && [ "$2" != "" ]; then
    OUTDEV="$2"
fi
if [ "$1" == "nat-1-1" ] && [ "$2" != "" ]; then
    OUTDEV="$2"
fi
if [ "$1" == "qos_start" ] && [ "$3" != "" ]; then
    OUTDEV="$3"
fi
SSHD_CONFIG="/etc/ssh/sshd_config"
DUMMY_IP="10.93.0.9"
CZELA_IP="10.93.0.0/16"
TC="/usr/sbin/tc"
IP="/usr/sbin/ip"
SYSCTL="/sbin/sysctl"
QOS_RATE="600000"
QOS_RATE_OUT="600000"

# Overime jestli existuji iptables
if [ ! -e $IPTABLES ]; then
    echo "Firewall not starting, $IPTABLES does not exist!"
fi

case "$1" in

start)
    echo -n "Starting firewall..."
    
    # Nejprve vse smazat
    $IPTABLES -F
    $IPTABLES -t nat -F
    $IPTABLES -t mangle -F
    $IPTABLES -X
    $IPTABLES -t nat -X
    $IPTABLES -t mangle -X

    # Zahazovat jen prichozi pakety
    $IPTABLES -P INPUT DROP
    $IPTABLES -P OUTPUT ACCEPT
    $IPTABLES -P FORWARD ACCEPT

    #navazana spojeni nebudeme zahazovat
    $IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    #$IPTABLES -A FORWARD -j LOG -m state --state NEW

    # lokalni siti, tunelum a loopbacku verime, zatim verime i NFX
    $IPTABLES -A INPUT -i lo -j ACCEPT
    $IPTABLES -A INPUT -i dummy0 -j ACCEPT
    $IPTABLES -A INPUT -i $INDEV -j ACCEPT
    $IPTABLES -A INPUT -i $INDEV1 -j ACCEPT

    # verejne IP
    $IPTABLES -A INPUT -d 78.108.96.0/22 -j ACCEPT
    $IPTABLES -A INPUT -s 78.108.96.0/22 -j ACCEPT
    $IPTABLES -A INPUT -d 78.108.100.0/24 -j ACCEPT
    $IPTABLES -A INPUT -s 78.108.100.0/24 -j ACCEPT

    # SSH
    $IPTABLES -A INPUT -p TCP --dport 22 -j ACCEPT
    $IPTABLES -A INPUT -p TCP --dport 2298 -j ACCEPT

    # Attack
    #$IPTABLES -A INPUT -p TCP --dport 673 -j DROP
    #$IPTABLES -A INPUT -p UDP --dport 673 -j DROP

    # ZEBRA (ospf, bgp, vty)
    $IPTABLES -A INPUT -p TCP --dport 2601 -j ACCEPT
    $IPTABLES -A INPUT -p TCP --dport 2604 -j ACCEPT
    $IPTABLES -A INPUT -p TCP --dport 2605 -j ACCEPT
    $IPTABLES -A INPUT -p TCP --dport 179 -j ACCEPT
    $IPTABLES -A INPUT -d 224.0.0.5/32 -j ACCEPT
    $IPTABLES -A INPUT -d 224.0.0.6/32 -j ACCEPT
    $IPTABLES -A INPUT -d 224.0.0.9/32 -j ACCEPT
    $IPTABLES -A INPUT -p ospf -j ACCEPT

    # ntest
    $IPTABLES -A INPUT -p udp --dport 5001:5010 -j ACCEPT
    $IPTABLES -A INPUT -p tcp --dport 5001:5010 -j ACCEPT
    
    # webtest
    $IPTABLES -A INPUT -p TCP --dport 80 -j ACCEPT

    # Spyware a viry na TCP portech
    for port in 17 19 135 137 139 445 1900
    do
	$IPTABLES -A FORWARD -p UDP --sport $port -j DROP
	$IPTABLES -A FORWARD -p UDP --dport $port -j DROP
	$IPTABLES -A FORWARD -p TCP --sport $port -j DROP
	$IPTABLES -A FORWARD -p TCP --dport $port -j DROP
    done
     
    #ICMP - ping
    $IPTABLES -N icmp_packets
    $IPTABLES -A INPUT -p ICMP -j icmp_packets
    $IPTABLES -A icmp_packets -p ICMP -j ACCEPT

    #ale limitovanej, aby nas nekdo neupinkal k smrti
    $IPTABLES -A icmp_packets -p ICMP --icmp-type echo-request -m limit --limit 1/s --limit-burst 5 -j ACCEPT

    #syn flood utok
    #$IPTABLES -N synflood
    #$IPTABLES -A synflood -m limit --limit 1/s --limit-burst 5 -j RETURN
    #$IPTABLES -A synflood -j DROP
    #$IPTABLES -A INPUT -p tcp --syn -j synflood

    #vochomurka natvrdo (mikael 20050315)
    #$IPTABLES -t nat -A POSTROUTING -o $OUTDEV -s 10.93.1.211 -j SNAT --to 78.108.96.2

    
    # NAT
    rm -f /tmp/nat_rules
    /etc/perl/ip_pool.pl > /tmp/nat_rules && sh /tmp/nat_rules

    #$IPTABLES -t nat -A POSTROUTING -o $OUTDEV -s 10.93.0.0/16 -j SNAT --to 78.108.96.1
    
    # ---------------------------------------------------------------------------
    while read A B; do
    	if [ "$A" == "PORT" ] || [ "$A" == "Port" ] || [ "$A" == "port" ] && [ "$B" != "22" ]; then
	    echo -n "ssh port $B detected..."
	    # Povolime aktualni port pro SSH a z cele site czela presmerujeme na aktualni port
	    $IPTABLES -A INPUT -p TCP --dport $B -j ACCEPT
	    $IPTABLES -t nat -A PREROUTING -p TCP -s $CZELA_IP -d $DUMMY_IP --dport 22 -j REDIRECT --to-ports $B
	    $IPTABLES -t nat -A PREROUTING -p TCP -s $CZELA_IP -d 10.93.1.193 --dport 22 -j REDIRECT --to-ports $B
	fi
    done < $SSHD_CONFIG
    #mikael 18:49
    #iptables -t nat -A PREROUTING -i eth1 -s 10.93.0.0/16 -p tcp --dport 80 -j DNAT --to 10.93.48.2:81
    #iptables -t nat -A POSTROUTING -o eth1 -s 10.93.0.0/16 -d 10.93.48.2 -j SNAT --to 10.93.0.10
    echo "done."

if false; then
    # kvuli sloane zakazani rozesilani spamu!
    $IPTABLES -I FORWARD -p tcp -m tcp --sport 25 -j DROP
    $IPTABLES -I FORWARD -p tcp -m tcp --dport 25 -j DROP

    # ale povolime aspon nektere nejpouzivanejsi
    "$0" allow_smtp smtp.seznam.cz
    "$0" allow_smtp smtp.email.cz
    "$0" allow_smtp smtp.volny.cz
    "$0" allow_smtp mail.centrum.cz
    "$0" allow_smtp ns.raca.cz
    "$0" allow_smtp mail.cleverapp.cz
    "$0" allow_smtp smtp.hogo.cz
    "$0" allow_smtp 10.93.9.229
    "$0" allow_smtp 10.93.101.10
fi


    #NAT 1:1
    $0 nat-1-1 "$OUTDEV"
    
    # blacklist
    . /etc/firewall/blacklist
    
    # start QOSu
    $0 qos_stop
    $0 qos_start
    
    # nastavime sysctl
    $SYSCTL -q -p

    # zakazeme p2p
    drop_p2p () {
	for protocol in $1; do
	    $IPTABLES -I FORWARD -i "$INDEV" -m layer7 --l7proto "$protocol" -j REJECT
	    $IPTABLES -I FORWARD -i "$INDEV1" -m layer7 --l7proto "$protocol" -j REJECT
	    $IPTABLES -I FORWARD -o "$OUTDEV" -m layer7 --l7proto "$protocol" -j REJECT
	done
    }
if false; then
    drop_p2p "directconnect bittorrent shoutcast gnutella gnucleuslan ares mute napster openft poco xunlei soulseek edonkey hotline"
fi
    ;;

stop)
    echo -n "Stoping firewall..."
    
    # Vsechna puvodni pravidla smazat
    $IPTABLES -F
    $IPTABLES -t nat -F
    $IPTABLES -X
    $IPTABLES -t nat -X

    # Vse povolit
    $IPTABLES -P INPUT ACCEPT
    $IPTABLES -P OUTPUT ACCEPT
    $IPTABLES -P FORWARD ACCEPT
    echo "done."
    ;;

restart)
    $0 stop
    $0 start
    ;;

nat-1-1)
    echo "Starting NAT 1:1... $OUTDEV"

    COMMENT="#"
    config=/etc/nat-1-1.conf
    
    if [ ! -e $config ]; then
	echo "Error, $config does not exist!"
    fi

    while read PublicIP PrivateIP UserName
    do
	FIRST_CHAR=`echo $PublicIP|cut -c1`
        if [ "$FIRST_CHAR" = "$COMMENT" ]; then
	    echo "$UserName commented"
        else
	    [ "$PROVIDER" == "SLOANE" ] && PublicIP="62.240.181.`echo $PublicIP | cut -d. -f4`"
    	    echo "$UserName ($PrivateIP -> $PublicIP)"
            $IPTABLES -t nat -I PREROUTING -d $PublicIP -j DNAT --to $PrivateIP
	    $IPTABLES -t nat -I POSTROUTING -o $OUTDEV -s $PrivateIP -j SNAT --to $PublicIP
    	    $IPTABLES -I FORWARD -d $PrivateIP -j ACCEPT
            # zaroven by bylo pekne zevnitr site na svou verejnou ip pingnout
	    [ "$DUMMY_IFACE" == "" ] && DUMMY_IFACE="dummy0"
            DUMMY_IP="`$IP addr show $DUMMY_IFACE | grep inet | grep -v inet6 | awk '{print \$2}' | cut -d \"/\" -f1`"
	    # zkusime resit problemy s padanim quaggy zakaznim tohoto pravidla pro adresy na optice 10.93.1.0/24
	    if [ "`echo $PrivateIP | cut -d. -f3`" != "1" ] && [ "$PrivateIP" != "10.93.0.1" ]; then
#    		$IPTABLES -t nat -I PREROUTING -i $INDEV -s $CZELA_IP -d $PublicIP -j DNAT --to $PrivateIP
        	$IPTABLES -t nat -I POSTROUTING -s $CZELA_IP -d $PrivateIP -j SNAT --to $DUMMY_IP
	    fi
	    # Povoleni smtp, ktere je pro normalni ip zakazane
	    $IPTABLES -I FORWARD -p tcp -m tcp -s $PrivateIP -j ACCEPT
	fi
    done < $config
    echo "done."
    ;;

qos_start)                                                                                                                                                        
    echo "Starting QoS..."

    [ "$2" != "" ] && QOS_RATE=$2
    
    for DEV in $INDEV $INDEV1 $OUTDEV; do
    echo "    $DEV rate $QOS_RATE type FD"
    
    if [ $DEV == $INDEV ] || [ $DEV == $INDEV1 ]; then
	SFQ="esfq hash dst"
    elif [ $DEV == $OUTDEV ]; then
	SFQ="esfq hash ctnatchg"
    else
	SFQ="sfq"
    fi
    
    # Vytvorime root qdisc                                                                                                                                        
    $TC qdisc add dev $DEV root handle 1:0 prio bands 3 priomap 2 2 2 2 2 2 0 0 2 2 2 2 2 2 2 2                                                                   
                                                                                                                                                                      
    # Ve trech zakladnich prio tridach vytvorime esfq pro nelimitovany traffic a htb pro limitovany                                                               
    $TC qdisc add dev $DEV parent 1:1 handle 11:0 $SFQ perturb 10
    $TC qdisc add dev $DEV parent 1:2 handle 12:0 $SFQ perturb 10
    $TC qdisc add dev $DEV parent 1:3 handle 13:0 htb default 111
	                                                                                                                                                                      
    # Zakladni htb tride dame plnou rychlost, dalsi budou mit rychlost sdilenou HTTP,mail, DC++,                                                                  
    $TC class add dev $DEV parent 13:0 classid 13:1 htb rate ${QOS_RATE}kbit
    $TC class add dev $DEV parent 13:1 classid 13:111 htb rate $[85*${QOS_RATE}/100]kbit ceil ${QOS_RATE}kbit #14000kbit
    $TC class add dev $DEV parent 13:1 classid 13:112 htb rate $[10*${QOS_RATE}/100]kbit ceil ${QOS_RATE}kbit #14000kbit
    $TC class add dev $DEV parent 13:1 classid 13:113 htb rate $[5*${QOS_RATE}/100]kbit ceil ${QOS_RATE}kbit #14000kbit
                                                         
		                                                                                                                                                                  
    # V kazde htb tride jeste pouziji esfq                                                                                                                        
    $TC qdisc add dev $DEV parent 13:111 handle 111:0 $SFQ perturb 10
    $TC qdisc add dev $DEV parent 13:112 handle 112:0 $SFQ perturb 10
    $TC qdisc add dev $DEV parent 13:113 handle 113:0 $SFQ perturb 10

    # Omarkovane pakety z iptables presmeruji do danych trid
    $TC filter add dev $DEV parent 1:0 protocol ip handle 1 fw flowid 1:1
    $TC filter add dev $DEV parent 1:0 protocol ip handle 2 fw flowid 1:2
    $TC filter add dev $DEV parent 13:0 protocol ip handle 3 fw flowid 13:111
    $TC filter add dev $DEV parent 13:0 protocol ip handle 4 fw flowid 13:112
    $TC filter add dev $DEV parent 13:0 protocol ip handle 5 fw flowid 13:113

    done

    # Markovani v iptables                                                                                                                                        
    mark_layer7 () {                                                                                                                                              
        for protocol in $2; do                                                                                                                                    
	    $IPTABLES -t mangle -I POSTROUTING -m layer7 --l7proto $protocol -j MARK --set-mark $1
        done                                                                                                                                                      
    }                                                                                                                                                             

    # ICMP                                                                                                                                                        
    $IPTABLES -t mangle -I POSTROUTING -p icmp -j MARK --set-mark 1                                                                                               
    # OSPF                                                                                                                                                        
    $IPTABLES -t mangle -I POSTROUTING -p ospf -j MARK --set-mark 1                                                                                               
    # UDP
    #$IPTABLES -t mangle -I POSTROUTING -p UDP -j MARK --set-mark 2                                                                                                
    # HTML                                                                                                                                                        
    #$IPTABLES -t mangle -A POSTROUTING -p TCP --dport 80 -j MARK --set-mark 3                                                                                    
    #$IPTABLES -t mangle -A POSTROUTING -p TCP --sport 80 -j MARK --set-mark 3                                                                                    
    mark_layer7 1 "bgp dhcp dns irc jabber ntp snmp yahoo h323 sip"                                                                                               
    mark_layer7 2 "battlefield1942 counterstrike-source dayofdefeat-source doom3 halflife2-deathmatch quake-halflife quake1 worldofwarcraft"
    mark_layer7 4 "ftp cvs imap live365 pop3 shoutcast smtp"
    mark_layer7 5 "100bao applejuice ares bittorrent directconnect edonkey gnutella mute msn-filetransfer napster poco smb soulseek xunlei http-itunes"
    # alespon trafik na amalku chceme mit bez QoSu
    $IPTABLES -t mangle -I POSTROUTING -o $INDEV -s 10.93.0.0/16 -j MARK --set-mark 1
    echo "done"                                                                                                                                                   
    ;;                                                                                                                                                            
                                                                                                                                                                  
qos_stop)                                                                                                                                                         
    echo -n "Stopping QoS..."
    # smazeme vsechna iptables pravidla                                                                                              
    for I in `$IPTABLES -t mangle -L POSTROUTING -n -v --line-numbers | grep "set 0x" | awk '{print $1}' | sort -r -n`; do           
        $IPTABLES -t mangle -D POSTROUTING $I                                                                                        
    done                                                                                                                             
    for I in `$IPTABLES -t mangle -L POSTROUTING -n -v --line-numbers | grep "todev" | awk '{print $1}' | sort -r -n`; do            
        $IPTABLES -t mangle -D POSTROUTING $I                                                                                        
    done                                                                                                                             
    for I in `$IPTABLES -t mangle -L PREROUTING -n -v --line-numbers | grep "todev" | awk '{print $1}' | sort -r -n`; do             
        $IPTABLES -t mangle -D PREROUTING $I                                                                                         
    done 
    # Smazu vsechny root qdisc                                                                                                                                    
    I="1"                                                                                                                                                         
    while true; do                                                                                                                                                
        if [ "`$TC qdisc | cut -d \" \" -f3 | grep 1: | sed -n ${I}p`" == "1:" ]; then                                                                            
            $TC qdisc del dev "`tc qdisc | grep 1: | cut -d \" \" -f5 | sed -n ${I}p`" root &>/dev/null                                                           
            $TC qdisc del dev "`tc qdisc | grep 1: | cut -d \" \" -f5 | sed -n ${I}p`" ingress &>/dev/null                                                        
        else                                                                                                                                                      
            break                                                                                                                                                 
        fi                                                                                                                                                        
        i="`expr 1 + $I`"                                                                                                                                         
    done                                                                                                                                                          
    # Deaktivuji vsechny imq zarizeni                                                                                                                             
    I="1"                                                                                                                                                         
    while true; do                                                                                                                                                
        if [ "`$IP link show | grep imq | cut -d \" \" -f 2 | cut -d: -f1 | sed -n ${I}p`" != "" ]; then                                                          
            $IP link set "`$IP link show | grep imq | cut -d \" \" -f 2 | cut -d: -f1 | sed -n ${I}p`" down                                                       
        else                                                                                                                                                      
            break                                                                                                                                                 
        fi                                                                                                                                                        
        I="`expr $I + 1`"                                                                                                                                         
    done                                                                                                                                                          
    rmmod -f imq &>/dev/null                                                                                                                                      
    echo "done."                                                                                                                                                  
    ;;

qos_restart)
    $0 qos_stop
    $0 qos_start $2 $3
    ;;
    
allow_smtp)
    echo -n "Povoluji odesilani emailu pres smtp server $2..."
    if [ "$2" != "" ]; then
	for I in `nslookup $2 | grep Address | grep -v "#" | awk '{print $2}'`; do
	    $IPTABLES -I FORWARD -p tcp -m tcp -s $I --sport 25 -j ACCEPT
	    $IPTABLES -I FORWARD -p tcp -m tcp -d $I --dport 25 -j ACCEPT
	done
    fi
    echo "done."
    ;;
*)
    echo "Usage: $0 {start|stop|restart|nat-1-1|macguard_check}"
    exit 1
    ;;

esac

exit 0

    
