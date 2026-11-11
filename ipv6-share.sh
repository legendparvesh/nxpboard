#!/usr/bin/env bash
# Share the laptop's IPv6 uplink with the FRDM board on the Ethernet port.
#
# The board does SLAAC (needs Router Advertisements) and talks to an
# IPv6-only server. This script:
#   * puts a ULA /64 on the Ethernet port and advertises it via dnsmasq RA
#   * enables IPv6 forwarding (keeping RA acceptance on the uplink)
#   * NAT66-masquerades board traffic out of the uplink
#
# Usage:  sudo ./ipv6-share.sh [up|down]   (env: LAN=enp0s31f6 WAN=wlp2s0)
set -euo pipefail

LAN=${LAN:-enp0s31f6}
WAN=${WAN:-wlp2s0}
PREFIX=fd00:f0ca:1::
ADDR=${PREFIX}1/64
PIDFILE=/run/ipv6-share-dnsmasq.pid

[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }

down() {
    [[ -f $PIDFILE ]] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
    rm -f "$PIDFILE"
    nft delete table ip6 ipv6share 2>/dev/null || true
    ip -6 addr del "$ADDR" dev "$LAN" 2>/dev/null || true
    sysctl -qw net.ipv6.conf.all.forwarding=0
    echo "ipv6-share: stopped"
}

up() {
    if ! ip -6 route show default dev "$WAN" | grep -q .; then
        echo "ERROR: $WAN has no IPv6 default route - the laptop itself has no IPv6 internet."
        echo "       Connect to a network with IPv6 first (phone hotspot, eduroam, ...)."
        exit 1
    fi

    # forwarding=1 normally makes the kernel ignore RAs; accept_ra=2 keeps the uplink working
    sysctl -qw "net.ipv6.conf.$WAN.accept_ra=2"
    sysctl -qw net.ipv6.conf.all.forwarding=1

    ip link set "$LAN" up
    ip -6 addr replace "$ADDR" dev "$LAN"

    nft -f - <<EOF
table ip6 ipv6share
delete table ip6 ipv6share
table ip6 ipv6share {
    chain postrouting {
        type nat hook postrouting priority srcnat;
        ip6 saddr ${PREFIX}/64 oifname "$WAN" masquerade
    }
    chain forward {
        type filter hook forward priority filter - 1;
        iifname "$LAN" oifname "$WAN" accept
        iifname "$WAN" oifname "$LAN" ct state established,related accept
    }
}
EOF
    # Docker sets the ip6 FORWARD policy to DROP in some setups; allow our flows there too
    if ip6tables -S FORWARD 2>/dev/null | grep -q -- '-P FORWARD DROP'; then
        ip6tables -C FORWARD -i "$LAN" -o "$WAN" -j ACCEPT 2>/dev/null || ip6tables -I FORWARD -i "$LAN" -o "$WAN" -j ACCEPT
        ip6tables -C FORWARD -i "$WAN" -o "$LAN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
            || ip6tables -I FORWARD -i "$WAN" -o "$LAN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    fi

    [[ -f $PIDFILE ]] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
    dnsmasq --port=0 --interface="$LAN" --bind-interfaces --except-interface=lo \
        --enable-ra --dhcp-range="::,constructor:$LAN,ra-only,64,1h" \
        --ra-param="$LAN,10,1800" --pid-file="$PIDFILE"

    echo "ipv6-share: advertising ${PREFIX}/64 on $LAN, NAT66 out of $WAN. Reset the board now (make reset)."
}

case "${1:-up}" in
    up) up ;;
    down) down ;;
    *) echo "usage: $0 [up|down]"; exit 1 ;;
esac
