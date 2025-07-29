# Network Analysis - Web Shell

## Scenario

The SOC received an alert in their SIEM for 'Local to Local Port Scanning' where an internal private IP began scanning another internal system. I was provided with a `.pcap` file and I investigated if this activity is malicious or not, using **Wireshark** in a Kali virtual machine.

## Analysis

I opened the `.pcap` file in **Wireshark** and searched for the packets that correspond to the port scanning activity, these are typically `TCP` packets. 
I started looking for `SYN` packets, which are typical for port scanning. I applied the filter `tcp.flags.syn == 1` and I found numerous `SYN` packets from the source IP  address `10.251.96.4`.

Next, I looked for the port range scanned by the suspicious host. To do that, I ordered the packets by the `Destination port` column and found a clear range of `1 - 1024`.

Since most of the packets are `SYN` and the rest are `SYN-ACK`, it indicates that the attacker is perfmorming a `SYN scan`, a stealthy scan that sends `SYN` packets to open ports but doesn't complete the `TCP handshake`, which is why it doesn't fully establish a connection.

To establish which tools were used to perform reconnaisance against open ports I started to search for signatures. First, I filtered `ip.dst == 10.251.96.5 && http.user_agent` to show all the packets with a user agent string to the target IP. 
I saw many `GET` request to different paths on the same domain, like `admin`, I inspected some of them and I found `gobuster 3.0.1` in the **User-Agent Header**.
To establish the second tool, I proceeded to another `gobuster` packets and notice a pattern with a URL with embedded SQL commands, a clear hint of a possilbe **SQL injection**: 

```
POST /?QLuT=8454%20AND%201%3D1%20UNION%20ALL%20SELECT%201%2CNULL%2C%27%3Cscript%3Ealert%28%22XSS%22%29%3C%2Fscript%3E%27%2Ctable_name%20FROM%20information_schema.tables%20WHERE%202%3E1--%2F%2A%2A%2F%3B%20EXEC%20xp_cmdshell%28%27cat%20..%2F..%2F..%2Fetc%2Fpasswd%27%29%23
```

A quick research told me that this is a typical **UNION SELECT** SQL injection payload designed to extract data from the database. The attacker is attempting to retrieve table names from the `information_schema.tables` table, which contains metadata about all tables in the database.

After analyzing the User agent I found another tool: `sqlmap 1.4.7`.

Next question is the name of the PHP file through wich the attacker uploaded a web shell. 