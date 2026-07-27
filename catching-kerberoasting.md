# Catching Kerberoasting

**Status:** Lab validated / experimental
**Lab:** `condef.local`
**Date:** 2026-07-25
**Platforms:** Windows Active Directory / Network
**Primary log sources:** Windows Security Event ID 4769 · Zeek `kerberos.log` through Malcolm
**Analysis tools:** Splunk · Arkime
**ATT&CK:** [T1558.003 – Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)

---

## TL;DR

I created eight Active Directory accounts with Service Principal Names and used Impacket's `GetUserSPNs.py` to request Kerberos service tickets for them.

The course example produced RC4 tickets, but my environment returned AES256. Kerberoasting does not require RC4, so I continued with the telemetry my domain actually generated rather than trying to force the result to match the example.

I detected the activity in Splunk as one account requesting tickets for eight distinct services within a short period. I then corroborated the same one-to-many pattern through Malcolm's network telemetry and cracked one captured AES256 ticket to recover the weak password protecting the service account.

---

## What Kerberoasting Is

Kerberoasting takes advantage of a normal Kerberos function.

An authenticated domain user can request a service ticket for an account that has a Service Principal Name, or SPN. Part of the returned ticket is encrypted using a key derived from the service account's password.

An attacker can save that ticket and test password guesses against it offline. The cracking process does not require additional communication with the domain controller and does not generate repeated failed logons.

If the service account uses a weak password, the attacker may recover it and gain whatever permissions belong to that account.

My goal was not only to execute the technique. I wanted to understand:

* What it produces in the domain controller's event logs
* What it looks like in network telemetry
* Which parts of the activity distinguish it from normal Kerberos authentication
* How the encryption type affects detection and cracking
* How to turn the observed behavior into a usable Splunk search

MITRE ATT&CK documents the technique as [T1558.003 – Kerberoasting](https://attack.mitre.org/techniques/T1558/003/).

---

## Setting Up the Lab

I used three virtual machines for the exercise:

| Host      | Role                                                       |
| --------- | ---------------------------------------------------------- |
| `DC`      | Domain controller, Windows event source, and Splunk server |
| `LinuxA`  | Attacker system running Impacket and Hashcat               |
| `Malcolm` | Network traffic collection and analysis                    |

To create Kerberoastable targets, I ran the course-provided PowerShell script on the domain controller.

The script created an Active Directory organizational unit and eight users with SPNs assigned to them.

![](images/01-spn-accounts-created.png)

These were disposable lab accounts created specifically to generate representative Kerberoasting telemetry. Their passwords were already known, and the accounts did not represent a real privilege-escalation path.

That distinction matters: the purpose of the exercise was to reproduce the observable ticket-requesting behavior, not to claim that I discovered unknown credentials in the environment.

---

## Running the Attack

I used Impacket's `GetUserSPNs.py` from `LinuxA`.

Before installing anything, I checked whether the tool was already available:

![](images/02-getuserspns-available.png)

I then ran:

```bash
GetUserSPNs.py condef.local/Administrator -dc-ip 192.168.137.135 -request -outputfile kerbtickets.txt
```

This command:

* Authenticated to `condef.local` as `Administrator`
* Located accounts with SPNs
* Requested service tickets for those accounts
* Saved the returned TGS-REP hash material to `kerbtickets.txt`

I examined the output with:

```bash
cat kerbtickets.txt
```

![](images/03-captured-hashes.png)

The file contained service-ticket material that could be tested offline with a password-cracking tool.

These are not copies of the accounts' stored password hashes. They are crackable representations of the encrypted Kerberos service tickets.

I used the Administrator account because that is how the course generated the telemetry for this exercise. Kerberoasting can be performed from a low-privileged domain account, but this specific execution was designed to reproduce the ticket-requesting, detection, and cracking workflow rather than the complete attack path.

---

## Finding the Activity in Splunk

When an account requests a Kerberos service ticket, the domain controller records Windows Security Event ID 4769.

My first query counted how many distinct services each account requested tickets for:

```spl
index=winlogs
| where EventCode = 4769
| stats dc(ServiceName) as TicketRequestedCount,
        values(ServiceName) as ServicesRequested
        by TargetUserName
```

![](images/04-4769-ticket-count.png)

This gave me:

* The account requesting the tickets
* The number of distinct services requested
* The names of those services

Event ID 4769 is generated during normal Kerberos authentication, so the presence of one event is not suspicious by itself.

The pattern that stood out in my lab was one account requesting tickets for eight different services within a short period.

That one-to-many request pattern became the primary behavioral signal for the detection.

---

## Examining the Encryption Type

Event ID 4769 also contains the `TicketEncryptionType` field.

![](images/05-ticket-encryption-type.png)

Microsoft documents the field in its [Event 4769 reference](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769).

Encryption type matters because RC4 tickets are faster to test with password-cracking tools than AES tickets. Kerberoasting tools and operators may therefore attempt to obtain RC4 tickets when the environment allows it.

RC4 is not required for Kerberoasting, however. AES service tickets can also be captured and cracked offline.

I added `TicketEncryptionType` to the query to determine what my execution produced:

```spl
index=winlogs
| where EventCode = 4769
| stats dc(ServiceName) as TicketRequestedCount,
        values(ServiceName) as ServicesRequested,
        values(TicketEncryptionType) as EncryptionTypes
        by TargetUserName
```

![](images/06-4769-with-enctypes.png)

The tickets generated in my environment used `0x12`, which represents AES256.

The course example produced RC4 tickets, but my domain continued returning AES256. This was not a failed execution. The ticket requests, Event ID 4769 telemetry, captured ticket material, and offline-cracking workflow were all present.

The difference was the encryption type selected by my environment.

---

## Translating the Encryption Values

The event records encryption types as hexadecimal values, so I used a Splunk `case` statement to translate them into readable names:

```spl
index=winlogs
| where EventCode = 4769
| eval Ticket_Type_Translate=case(
    TicketEncryptionType="0x1", "DES-CBC-CRC",
    TicketEncryptionType="0x3", "DES-CBC-MD5",
    TicketEncryptionType="0x11", "AES128-CTS-HMAC-SHA1-96",
    TicketEncryptionType="0x12", "AES256-CTS-HMAC-SHA1-96",
    TicketEncryptionType="0x17", "RC4-HMAC",
    TicketEncryptionType="0x18", "RC4-HMAC-EXP",
    true(), TicketEncryptionType
)
| stats dc(ServiceName) as TicketRequestedCount,
        values(ServiceName) as ServicesRequested,
        values(Ticket_Type_Translate) as EncryptionTypes
        by TargetUserName
```

![](images/07-4769-enctypes-translated.png)

This confirmed that my Kerberoasting execution produced AES256 tickets.

Legitimate ticket requests in my environment also used AES256. That meant AES256 was not the malicious signal by itself.

The stronger signal was the requesting behavior:

> One account requested tickets for many distinct services within a short period.

Encryption type remained useful context, but the ticket volume and service fan-out provided the more general detection opportunity.

---

## Building the Detection

I grouped the events into one-hour buckets and counted the number of distinct services requested by each account.

During the original lab validation, I used this query:

```spl
index=winlogs EventCode=4769 TicketEncryptionType="0x12"
| bin span=1h _time
| stats dc(ServiceName) as TicketRequestedCount,
        values(ServiceName) as ServicesRequested
        by TargetUserName, _time
| where TicketRequestedCount > 5
```

![](images/08-kerberoast-alert.png)

The query successfully identified my execution:

* `Administrator@CONDEF.LOCAL` requested the tickets
* Eight distinct service accounts were targeted
* The requests occurred within the same one-hour bucket
* The tickets used AES256

This validated that the behavior was visible and searchable in my environment.

However, the AES256 filter was specific to the result I observed. It was not the behavior that made the activity suspicious.

A more general version of the detection is:

```spl
index=winlogs EventCode=4769
| eval Ticket_Type_Translate=case(
    TicketEncryptionType="0x1", "DES-CBC-CRC",
    TicketEncryptionType="0x3", "DES-CBC-MD5",
    TicketEncryptionType="0x11", "AES128-CTS-HMAC-SHA1-96",
    TicketEncryptionType="0x12", "AES256-CTS-HMAC-SHA1-96",
    TicketEncryptionType="0x17", "RC4-HMAC",
    TicketEncryptionType="0x18", "RC4-HMAC-EXP",
    true(), TicketEncryptionType
)
| bin span=1h _time
| stats dc(ServiceName) as TicketRequestedCount,
        values(ServiceName) as ServicesRequested,
        values(Ticket_Type_Translate) as EncryptionTypes
        by TargetUserName, _time
| where TicketRequestedCount > 5
```

This version retains encryption type as analyst context but does not require either RC4 or AES.

It can therefore identify the high-volume service-ticket behavior regardless of which supported encryption type the domain controller returns.

The threshold of more than five distinct services is based only on the behavior observed in my lab. It is not a production recommendation and would require environmental baselining before operational use.

---

## Why the Detection Works

Bulk Kerberoasting requires the attacker to request service tickets for accounts with SPNs.

Each request creates Event ID 4769 on the domain controller.

The detection looks for three related characteristics:

1. One requesting account
2. Many distinct service names
3. Requests occurring within a limited period

The technique can be performed with different tools and encryption types, but the requests still have to occur.

Encryption type can change the confidence of the result:

* RC4 may be highly suspicious in an environment where legitimate systems normally use AES.
* AES cannot be treated as safe because AES tickets can still be cracked offline.
* A burst of requests for many SPNs may be suspicious regardless of encryption type.

The account, service names, encryption type, timing, source system, and environmental baseline should therefore be evaluated together.

---

## The Network View

I also investigated the activity from the network perspective using Malcolm.

Because my execution produced AES256 tickets, I searched Arkime with:

```text
zeek.kerberos.cipher == aes256-cts-hmac-sha1-96 && zeek.kerberos.request_type == TGS
```

![](images/09-arkime-search.png)

In the Connections view, I set:

```text
Source: zeek.kerberos.cname
Destination: zeek.kerberos.sname
```

This graphed the requesting account against the services for which it requested tickets:

![](images/10-arkime-connection-graph.png)

The graph showed `Administrator/CONDEF.LOCAL` fanning out to the accounts created for the Kerberoasting exercise.

That was the same one-to-many pattern I observed in Splunk:

* One requesting account
* Multiple service accounts
* Requests occurring close together

Splunk showed the activity from the domain controller's Windows event logs. Malcolm showed it through independently collected network telemetry.

Having both sources show the same behavior increased my confidence that I had correctly identified the execution.

---

## Cracking an AES256 Ticket

The course exercise focused on generating and detecting the Kerberoasting telemetry. Cracking the tickets was not required, but I continued to the offline-cracking stage.

My captured tickets used AES256, corresponding to Kerberos encryption type 18. The matching Hashcat mode is `19700`.

My attacker VM was CPU-only, so I extracted one ticket into a separate file and ran:

```bash
hashcat -m 19700 -a 0 onehash.txt rockyou.txt --force
```

![](images/11-hashcat-cracked.png)

Hashcat ran at approximately 12,000 guesses per second and recovered the password `Password123!` for the `User1` account.

That completed the technical workflow demonstrated in my lab:

1. Create accounts with SPNs
2. Request service tickets
3. Save the returned TGS-REP material
4. Detect the requests in Windows telemetry
5. Corroborate the requests in network telemetry
6. Test a captured ticket offline
7. Recover the weak service-account password

AES made each password guess more computationally expensive than RC4 would have, but it did not protect a weak password from being recovered.

Strong, unique service-account passwords remain necessary even when AES is used.

---

## False Positives and Tuning

Requesting several service tickets is not automatically malicious.

Potential benign causes include:

* Administrative scripts that connect to several services
* Monitoring and management platforms
* Service-discovery processes
* Applications that authenticate to multiple back-end services
* Accounts that legitimately interact with many SPNs
* Authorized security testing

Before using this detection outside the lab, I would baseline:

* The normal number of distinct services requested by each account
* Accounts that routinely request high ticket volume
* Expected source systems
* Expected service names
* Normal encryption types
* Differences between human, machine, and service accounts
* Time-of-day and scheduled-task patterns

I would avoid broadly allowlisting a high-volume account solely because the behavior is common. If that account were compromised, the exclusion could hide malicious ticket requests.

Any allowlist should be narrow, documented, and regularly reviewed.

---

## Limitations

### Low-volume targeting

An attacker may request only one or two high-value service tickets and remain below the threshold.

### Slow Kerberoasting

An attacker can distribute the requests over a longer period to avoid producing an obvious burst.

### Fixed time buckets

The one-hour `bin` command creates fixed buckets. Related events near the boundary between two buckets may be separated.

### Lab-specific threshold

The threshold of more than five distinct services was selected from a small lab environment. A production domain may have very different normal behavior.

### Encryption type is not definitive

RC4 may increase suspicion, but AES tickets can also be Kerberoasted. Neither encryption type proves or disproves malicious activity by itself.

### Telemetry dependencies

The host-side detection depends on Event ID 4769 being generated, collected, parsed, and retained.

The network-side investigation depends on visibility into the Kerberos traffic and correctly parsed Zeek telemetry.

### Representative execution

I authenticated to `GetUserSPNs.py` as the domain Administrator because the goal of the lab was to generate representative telemetry.

This execution did not demonstrate the complete attack path beginning with a compromised low-privileged user. It successfully demonstrated the ticket-requesting, detection, network-correlation, and offline-cracking stages.

---

## Analyst Investigation

If this detection fired, I would investigate:

1. Which account requested the tickets?
2. Which system or IP address originated the requests?
3. Which service accounts were targeted?
4. How many distinct services were requested?
5. How quickly did the requests occur?
6. Which encryption types were returned?
7. Is this volume normal for the requesting account?
8. Are the targeted service accounts privileged?
9. Does the source system show related discovery or credential-access activity?
10. Has the requesting account shown other signs of compromise?
11. Can the ticket requests be explained by an approved application or administrative process?
12. Do the targeted service accounts use strong, managed passwords?

The alert would become more suspicious if:

* The requesting account normally contacts very few services
* The source system is unusual
* The targeted accounts are highly privileged
* RC4 is rare in the environment
* The source also performed Active Directory discovery
* The requests occurred outside normal operating hours

---

## Key Takeaways

* I successfully completed the Kerberoasting telemetry exercise even though my environment returned AES256 instead of the RC4 result shown in the course.
* Kerberoasting does not require RC4. AES service tickets can also be captured and cracked offline.
* Event ID 4769 exposes the requesting account, requested service, and ticket encryption type.
* In my lab, the strongest signal was one account requesting tickets for eight distinct services within a short period.
* The AES256 filter worked for validating my specific execution, but the generalized behavioral detection should not require one encryption type.
* Splunk and Malcolm independently showed the same one-to-many ticket-request pattern.
* Cracking one captured ticket demonstrated that AES cannot compensate for a weak service-account password.
* The threshold and tuning decisions are specific to my lab and would require production baselining.
* The exercise generated representative Kerberoasting telemetry rather than reproducing a complete low-privilege attack path.
* Producing a different encryption result forced me to analyze my own telemetry instead of copying the course's expected output.

---

## References

* [MITRE ATT&CK T1558.003 – Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
* [Microsoft – Event 4769: A Kerberos service ticket was requested](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
* [The Hacker Recipes – Kerberoast](https://www.thehacker.recipes/ad/movement/kerberos/kerberoast)
* [TrustedSec – The Art of Bypassing Kerberoast Detections with Orpheus](https://www.trustedsec.com/blog/the-art-of-bypassing-kerberoast-detections-with-orpheus)
* [Lares – Active Directory Attacks: Enumeration at the Network Layer](https://www.lares.com/blog/active-directory-ad-attacks-enumeration-at-the-network-layer/)
