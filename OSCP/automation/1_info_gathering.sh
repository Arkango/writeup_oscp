#!/bin/bash

# $1 network

mkdir ../results 


network_orig=$1 
network=$(echo $1 | tr '\/' '_')

mkdir ../results/$network



function host_discovery_nmap(){
    mkdir ../results/$network/nmap
    nmap -sn -Pn -oA ../results/$network/nmap/ $network_orig 
}

function host_discovery_crackmapexec(){
    mkdir ../results/$network/crackmapexec
    crackmapexec smb $network_orig  > ../results/$network/crackmapexec/out_file
}


function host_discovery_pingsweep(){
    base_n=$(echo $network_orig | awk -F '/' '{print$1}' | awk -F '.' '{print$1.$2.$3}')
    for i in {1..255};do (ping -c 1 $base_n.$i | grep "bytes from" &); done
}



# HOST DISCOVERY
host_discovery_nmap
host_discovery_crackmapexec
host_discovery_pingsweep

function quick_port_scanning_nmap(){
    mkdir ../results/$network/nmap_ps
    nmap -sC -sV -A -Pn -T5  $network_orig -oA ../results/quick$network/nmap_ps/ -vvv
}

function quick_port_scanning_nmap_udp(){
    mkdir ../results/$network/nmap_ps
    nmap -sC -sV -sU -A -Pn -T5  $network_orig -oA ../results/quickudp$network/nmap_ps/ -vvv
}

function port_scanning_nmap(){
    mkdir ../results/$network/nmap_ps
    nmap -sC -sV -A -Pn -T5 -p- $network_orig -oA ../results/full$network/nmap_ps/ -vvv
}

# PORT SCANNING
quick_port_scanning_nmap
quick_port_scanning_nmap_udp
port_scanning_nmap
# ?? rustscan





# DNS Enumeration

function host_domain(){
    host $network_orig
    host -t mx $network_orig
    host -t txt $network_orig
}

function forward_lookup_bf(){

    for ip in $(cat wordlist.txt); do host $ip.$network_orig; done
}

function reverse_lookup_bf(){
    base_n=$(echo $network_orig | awk -F '/' '{print$1}' | awk -F '.' '{print$1.$2.$3}')

    for ip in $(seq  50 100); do host 192.168.0.$base_n; done | grep -v "not found"
}


function dns_server(){
    host -t ns $network_orig | cut -d " " -f 4
}

function dns_zone_transfer(){
    host -l $network_orig  8.8.8.8

}

function dns_zone_transfer_dnsrecon(){
    dnsrecon -d $network_orig -t axfr
    dnsrecon -d $network_orig -D wordlist.txt -t brt
}


host_domain
forward_lookup_bf
reverse_lookup_bf
dns_server
dns_zone_transfer
dns_zone_transfer_dnsrecon


#SMB enumeration

function smb_enum(){
    nmap -v -p 139,445 -oG smb.txt $network_orig
}

function smb_nbtscan(){
    sudo nbtscan -r $network_orig
}

function smb_enum4linux(){
    enum4linux $network_orig
    enum4linux -a -u "" -p "" $network_orig && enum4linux -a -u "guest" -p "" $network_orig
}

smb_enum
smb_nbtscan
smb_enum4linux


#NFS enumeration

function nsf_version(){
    nmap -sV -p 111 --script=rpcinfo $network_orig
    rpcinfo $network_orig| grep nfs

}

function nfs_shared_dir(){
    nmap -p 111 --script nfs* $network_orig
    showmount -e $network_orig

}


#### 


##mount mkdir /tmp/ok; sudo mount -t nfs -o vers=4 <IP>:/folder /tmp/ok -o nolock

##config /etc/exports, /etc/lib/nfs/etab

###


#LDAP enumeration


function ldap_enum(){
    nmap -n -sV --script "ldap* and not brute" $network_orig
    ldapsearch -h $network_orig -bx "DC=domain,DC=com"

}

ldap_enum


#SNMP enumeration 

function snmp_enum(){
    sudo nmap -sU --open -p 161 $network_orig -oG open-snmp.txt
    echo public > community
    echo private >> community
    echo manager >> community

    base_n=$(echo $network_orig | awk -F '/' '{print$1}' | awk -F '.' '{print$1.$2.$3}')


    for ip in $(seq 1 243); do echo $base.$ip; done > ips
    onesixtyone -c community -i ips
    onesixtyone -c community -i ips
}

function enum_entire_mib_tree(){
    snmpwalk -c public -v1 -t $network_orig
}

function enum_entire_windows_user(){
    snmpwalk -c public -v1 $network_orig 1.3.6.1.4.1.77.1.2.25
}

function list_running_process(){
    snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.25.4.2.1.2

}

function list_open_tcp_port(){
    snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.6.13.1.3

}

function enumerate_installed_sw(){
    snmpwalk -c public -v1 <ip> 1.3.6.1.2.1.25.6.3.1.2

}


snmp_enum
enum_entire_mib_tree
enum_entire_windows_user
list_running_process
list_open_tcp_port
enumerate_installed_sw


#FTP enumeration

#default creds anonymous : anonymous
# binary for binary transfer
# ascii for ascii transfer

function enum_ftp(){
    nc <IP> <PORT>
    nmap --script ftp-* -p 21 <ip>
}


#RDP enumeration


function enum_rdp(){
nmap --script rdp-ntlm-info,rdp-enum-encryption,rdp-vuln-ms12-020 -p 3389 -T4 <IP>

}



# > Connect to RDP

# rdesktop -u <username> <IP>
# xfreerdp /d:<domain> /u:<username> /p:<password> /v:<IP>


# -> Check valid credentials in RDP

# rdp_check <domain>/<name>:<password>@<IP>


#POP enumeration 

function enum_pop(){
 nmap --script pop3-capabilities,pop3-ntlm-info -sV -port <IP>

}


# -> login

# telnet <IP> 110
# USER user1
# PASS password
# -> list messages

# list
# -> Show message number 1

# retr 1



#SMTP enumeration


function smtp_enum(){
    nmap -p25 --script smtp-commands,smtp-open-relay 10.10.10.10

}


# -> send email via SMTP

# nc -C <IP> 25
# HELO
# MAIL FROM:user@local
# RCPT TO:user2@local
# DATA
# Subject: approved in the job

# http://<IP>/malware.exe

# .
# QUIT
# hydra smtp-enum://192.168.0.1/vrfy -l john -p localhost -> username enumeration

# telnet 10.0.0.1 25
# HELO
# hydra smtp-enum://<IP>/vrfy -L "/usr/share/seclists/Usernames/top-usernames-shortlist.txt" 


#web enum

# ffuf -u http://site.com/FUZZ -w /usr/share/wordlists/dirb/big.txt


# -> Fuzzing File Extension

# ffuf -u "https://site.com/indexFUZZ" -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt -fs xxx
# -> Fuzzing Parameter GET

# ffuf -u "https://site.com/index.php?FUZZ=ok" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
# -> Fuzzing Parameter POST

# ffuf -u "https://site.com/index.php" -X POST -d 'FUZZ=ok' -H 'Content-Type: application/x-www-form-urlencoded' -w wordlist.txt -fs xxx