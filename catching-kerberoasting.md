# Catching Kerberoasting

**Lab:** `condef.local`
**Date:** 2026-07-25
**Platform(s):** Windows Active Directory / Network
**Primary log source(s):** Windows Security (Event ID 4769) · Zeek `kerberos.log` (via Malcolm)
**SIEM:** Splunk (host) · Arkime (network)
**ATT&CK:** [T1558.003, Kerberoasting] · Tactic: Credential Access

---

## TL;DR

Any domain user can request a service ticket for an account that has an SPN, and that ticket comes back encrypted with the account's password, so the weak ones can be cracked offline. Whatever tool runs the attack, it has to make those requests, and they land as a burst of Event ID 4769s: one account asking the DC for tickets to many different SPNs in a short window. That burst is the primitive I built the detection on, caught on the host in Splunk and on the wire in Malcolm, and I finished by cracking a captured ticket back to its plaintext password.

## What it is

I didn't know what kerberoasting was going in, so here is how I understand it now. Any account in the domain can ask for a ticket to reach a service, and that ticket comes back locked with the service account's password. So even as a nobody user, I can ask for tickets to service accounts I have no real business touching, carry the encrypted tickets off the network, and try to crack them at my own pace. If a service account has a weak password, I get its plaintext, and now I have whatever that account can do. That is the whole move: a low priv account turning into a real one by cracking a ticket it was allowed to ask for in the first place.

I am less interested in pulling off the attack than in seeing what it leaves behind. The goal here is to run a roast in my own lab and come out the other side knowing two things: exactly what its telemetry looks like, and how to actually build a detection for it, on the host side in Splunk and on the network side in Malcolm. So that if it showed up for real, I would both recognize it and know how to catch it.

Mitre's info page on this technique: https://attack.mitre.org/techniques/T1558/003/

## Setting it up

To have something worth roasting, I need some accounts with SPNs set, so I create a handful on the DC. I open up Windows PowerShell ISE on the DC, paste the script in, and run it.

![](images/01-spn-accounts-created.png)

For this I have three of my VMs up: the DC, my capture box (Malcolm), and my attacker box (LinuxA).

## Running the attack

For the attack itself I used Impacket's GetUserSPNs, run from my attacker box (LinuxA). Impacket is a widely used set of Python tools for working with Windows network protocols, and GetUserSPNs is the one that does the roast: it finds the accounts that have an SPN set and requests a service ticket for each. Before installing anything I checked whether it was already on the box.

![](images/02-getuserspns-available.png)

It's there and available so I run:

```
GetUserSPNs.py condef.local/Administrator -dc-ip 192.168.137.135 -request -outputfile kerbtickets.txt
```

Then I look at the output file with `cat kerbtickets.txt`:

![](images/03-captured-hashes.png)

There they are, the crackable password hashes for each of the SPN accounts. I come back to cracking one at the end. First though, the part I actually care about is what this whole thing left behind in the logs.

## Finding it in Splunk

Every time an account asks the DC for a service ticket, the DC writes an Event ID 4769. That single event is what the whole detection hangs on. My first pass just counts how many distinct services each account asked for a ticket for:

```spl
index=winlogs
| where EventCode = 4769
| stats dc(ServiceName) as TicketRequestedCount,values(ServiceName) as ServicesRequested by TargetUserName
```

![](images/04-4769-ticket-count.png)

This gives me the account doing the asking, how many tickets it pulled, and which services it pulled them for.

The reason this stands out to me is that a normal user asks for a ticket when they actually go to use a service. One account asking for tickets to eight different services in a short window is not how normal use looks, and that is the thing I want to catch.

There is one more field on the 4769 worth pulling in, TicketEncryptionType.

![](images/05-ticket-encryption-type.png)

Microsoft's documentation on it: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769

Here is why that field matters. The whole point of the roast is to crack the ticket, and RC4 is far easier to crack than AES, so a lot of roasting tools deliberately ask for the RC4 version of the ticket. It is not a rule though. AES tickets can be roasted too, they are just slower to crack. In my own run the tickets all came back AES256, because my service accounts are AES capable and the DC hands back a ticket encrypted with the strongest key the account supports. So I built my detection around the AES case.

I pulled the encryption type into the query to see what my own tickets actually were:

```spl
index=winlogs
| where EventCode = 4769
| stats dc(ServiceName) as TicketRequestedCount,values(ServiceName) as ServicesRequested,values(TicketEncryptionType) as EncryptionTypes by TargetUserName
```

![](images/06-4769-with-enctypes.png)

The raw values are hex, so I had Splunk map them to their readable names with a case statement:

```spl
index=winlogs
| where EventCode = 4769
| eval Ticket_Type_Translate = case(TicketEncryptionType="0x12","AES256-CTS-HMAC-SHA1-96",TicketEncryptionType="0x1","DES-CBC-CRC",TicketEncryptionType="0x3","DES-CBC-MD5",TicketEncryptionType="0x11","AES128-CTS-HMAC-SHA1-96",TicketEncryptionType="0x12","AES256-CTS-HMAC-SHA1-96",TicketEncryptionType="0x17","RC4-HMAC",TicketEncryptionType="0x18","RC4-HMAC-EXP")
| stats dc(ServiceName) as TicketRequestedCount,values(ServiceName) as ServicesRequested,values(Ticket_Type_Translate) as EncryptionTypes by TargetUserName
```

![](images/07-4769-enctypes-translated.png)

Binning by the hour, one bucket jumps right out with eight ticket requests from a single account. Pretty suspicious.

With a feel for what normal looks like in here, I can turn this into an actual alert:

```spl
index=winlogs EventCode=4769 TicketEncryptionType="0x12"
| bin span=1h _time
| stats dc(ServiceName) as TicketRequestedCount, values(ServiceName) as ServicesRequested by TargetUserName, _time
| where TicketRequestedCount > 5
```

This narrows to the encryption type I am dealing with and only fires when one account asked for more than five tickets inside an hour bucket.

![](images/08-kerberoast-alert.png)

## The network view

I also wanted to see the roast on the network, not just in the DC's logs. The nice part is that Kerberos puts the account name and the service name in the clear on the wire, and only the ticket itself is encrypted, so I can spot the same thing from the network without touching the DC's logs at all. Over in Malcolm I searched Arkime:

```
zeek.kerberos.cipher == aes256-cts-hmac-sha1-96 && zeek.kerberos.request_type == TGS
```

![](images/09-arkime-search.png)

Then in the Connections tab I set the source node to `zeek.kerberos.cname` and the destination to `zeek.kerberos.sname`, which graphs each requesting account against the services it asked for:

![](images/10-arkime-connection-graph.png)

The account doing the roasting is Administrator/CONDEF.LOCAL, and everything it points at is an account I roasted. One account fanning out to a whole cluster of service names at once is the roast, and it is the same picture Splunk gave me, just from the network side instead of the DC.

## Cracking a ticket

Earlier I said I would come back to cracking one, so here it is. A captured ticket only matters if the password behind it is weak enough to crack, so I wanted to take one all the way to plaintext.

My hashes came back as AES256, so the matching hashcat mode is 19700 (Kerberos 5, etype 18, TGS-REP). My attacker box is CPU only with no GPU, so I ran with `--force`. I pulled a single hash out into its own file so it would crack faster, then ran it against a wordlist:

```
hashcat -m 19700 -a 0 onehash.txt rockyou.txt --force
```

![](images/11-hashcat-cracked.png)

It ran at around 12,000 guesses per second and recovered the password, `Password123!`, for the User1 account. That closes the technical loop: I generated the service-ticket requests, captured an AES256 ticket, and recovered the weak password protecting the service account.

For this lab exercise, I authenticated to `GetUserSPNs.py` with the domain Administrator account to generate representative Kerberoasting telemetry. This execution therefore demonstrates the ticket-requesting, detection, and offline-cracking workflow, but it does not reproduce the full attack path from a low-privileged account.

## Key takeaways

- Going through this start to finish, I now know the footprint a roast leaves behind. In the host logs it is a burst of 4769s from one account, each with its encryption type on it, and on the network it is that same one to many fan-out from a single account to a pile of services. That is the shape I would look for to catch this again, and knowing what the telemetry actually looks like is the whole point of running the attack in my own lab instead of just reading about it.
- In an AES domain, the thing that really flags the roast is volume, one account pulling many distinct service tickets in a short window, more than the encryption type on its own. Every legitimate ticket is AES256 too, so it is the count that stands out.
- I now know how to build this detection myself, not just describe it. In Splunk that meant working the 4769s from a rough count up to a tuned alert, and in Malcolm it meant pulling the same activity up as a connection graph straight off the traffic. Two different tools and two different query styles for the same attack, and having the host logs and the network view agree from completely separate sources is exactly the corroboration I would want on a real alert.
- Cracking one ticket made the risk concrete. Going from a normal user's ticket request to a service account's cleartext password is the whole point of the attack, and the slow AES crack speed is the argument for keeping service accounts on AES and on strong passwords.

## References

- [The Hacker Recipes - Kerberoast](http://www.thehacker.recipes/ad/movement/kerberos/kerberoast)
- [TrustedSec - The Art of Bypassing Kerberoast Detections with Orpheus](https://www.trustedsec.com/blog/the-art-of-bypassing-kerberoast-detections-with-orpheus)
- [Lares - Active Directory Attacks Enumeration at the Network Layer](https://www.lares.com/blog/active-directory-ad-attacks-enumeration-at-the-network-layer/)
