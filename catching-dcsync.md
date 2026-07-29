# Catching DCSync: Detecting Domain Replication Abuse

**Lab:** `condef.local` · **Platform:** Windows / Active Directory · **Log sources:** Windows Security (4662, 4769), Zeek/Arkime network capture · **SIEM:** Splunk · **ATT&CK:** T1003.006 (OS Credential Dumping: DCSync) · Tactic: Credential Access

## TL;DR

DCSync lets an attacker pretend to be a domain controller and ask a real DC to hand over account password data through the normal AD replication protocol. The detection primitive is simple once you see it: a directory replication request (the "Replicating Directory Changes" rights) coming from something that is not a domain controller. Whatever tool runs the attack, it has to make that replication call, and only DCs are supposed to. I caught it two ways in my lab, on the DC's Windows logs and independently on the network capture, and along the way I learned that my detection query was useless until I turned on the log source feeding it.

## What DCSync is

DCSync abuses Active Directory replication. When two domain controllers need to stay in sync, one asks the other to send over directory changes. That is a legitimate, built-in protocol. DCSync takes advantage of it: instead of reading credentials out of memory on a machine like I did with LSASS dumping, it sends a replication request over the network and asks the DC to send back the secrets for an account. The DC answers, because the request looks like it came from another DC.

I ran it with Mimikatz, a credential-access tool that, among many other things, can perform this replication pull. If I target the built-in Administrator or the `krbtgt` account, the data that comes back is enough to forge Kerberos tickets and move around the domain at will, which is why DCSync is treated as a domain-compromise-level event. Real intrusions use it for exactly that reason: it pulls high-value credentials while blending in with traffic the domain is supposed to see.

## Running the attack

I ran the attack from win11a against the DC. The command:

```
lsadump::dcsync /domain:condef.local /user:Administrator
```

![Mimikatz DCSync output showing the Administrator NTLM hash and Kerberos keys](images/01-mimikatz-dcsync-output.png)

Mimikatz impersonated the DC and pulled the Administrator account. What came back:

- **NTLM hash** (`64f12c...`): the actual hash of the Administrator password. It does not need cracking. With pass-the-hash, the hash itself works as the credential.
- **aes256 / aes128 Kerberos keys**: the material used for overpass-the-hash or forging tickets.
- **Password last change: 7/2/2026**: tells me how current the hash is.

The account is the built-in Administrator, RID 500 (shown as `Object Relative ID: 500`). Pulling its Kerberos keys is the raw material for a Golden Ticket, so this one account is a big deal on its own.

## Detecting it on the DC (Event 4662)

The first place I looked was event 4662, "an operation was performed on an object." This event carries GUIDs in its Properties field that map to the specific rights used. For DCSync the one I care about is `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`, which is the DS-Replication-Get-Changes-All right. I used a domain admin account for this, which already has that right. Worth remembering that in a real network, lower-privileged accounts sometimes end up with this right through troubleshooting or old technical debt, so this is not only a domain-admin problem.

My detection query keys on that GUID, filters out normal noise, and joins in logon context:

```spl
index=winlogs EventCode=4662 AND NOT (SubjectUserSid="NT AUTHORITY\LOCAL SERVICE" AND SubjectDomainName="Window Manager")
(
  (ObjectType="%{19195a5b-6da0-11d0-afd3-00c04fd930c9}" OR ObjectType="domainDNS")
  AND
  (Properties="*Replicating Directory Changes All*" OR Properties="*{1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}*" OR Properties="*{9923a32a-3607-11d2-b9be-0000f87a36b2}*" OR Properties="*{1131f6ac-9c07-11d1-f79f-00c04fc2dcd2}*")
)
| rename _time AS DSTime, SubjectUserSid AS DSUserSid, SubjectDomainName AS DSDomainName, SubjectUserName AS DSUserName, SubjectLogonId AS DSLogonId, ObjectType AS DSObjectType, ObjectName AS DSObjectName, Properties AS DSProperties, status AS DSStatus
| join type=left Computer, DSLogonId
[
    search index=winlogs AND EventCode=4624 NOT (SubjectUserSid="S-1-5-19" OR SubjectDomainName="Window Manager")
    | rename _time AS LogonTime, TargetLogonId AS DSLogonId
]
| convert timeformat="%d/%m/%Y %H:%M:%S" ctime(DSTime), ctime(LogonTime)
| eval src_ip = replace(IpAddress, "^::ffff:", "")
| eval IsDC = case(
    src_ip=="192.168.137.138", "Not a DC (win11a workstation)",
    src_ip=="192.168.137.135", "DC",
    isnull(src_ip) OR src_ip=="", "No source IP in 4624 (Kerberos logon)",
    true(), "Unknown host")
| table DSTime, Computer, DSUserSid, DSDomainName, DSUserName, DSObjectType, DSObjectName, DSProperties, DSStatus, DSLogonId, LogonTime, AuthenticationPackageName, src_ip, IpPort, IsDC
```

### It returned nothing, and figuring out why was the real lesson

I ran that and got **no results**. The attack had just fired, so something was off.

![Full detection query returning zero results](images/02-detection-query-zero-results.png)

First thing I did was strip the query down to just the event code to see if 4662 was even present:

```spl
index=winlogs EventCode=4662
```

![Bare 4662 search also returning zero results](images/03-bare-4662-zero-results.png)

Still nothing. So either the pipeline was broken or the DC was not generating 4662 at all. I did a sanity check to make sure Windows events were reaching Splunk:

```spl
index=winlogs
```

![winlogs index populated with 634 events from host DC](images/04-winlogs-pipeline-healthy.png)

634 events, sourcetype `XmlWinEventLog:Security`, host DC. The pipeline was healthy. So this was not a forwarding problem. The DC simply was not producing 4662. I could even see the clue in what I did have: plenty of 5145 (network share access) events but no 4662, which meant object-access auditing was partly on but the specific piece that produces 4662 was not.

That piece is the Directory Service Access audit subcategory. I checked it on the DC in PowerShell:

```
auditpol /get /subcategory:"Directory Service Access"
```

![auditpol showing Directory Service Access set to No Auditing](images/05-ds-access-auditing-off.png)

**No Auditing.** That was the answer. Event 4662 only fires when Directory Service Access auditing is on, so DCSync had been running completely silent. My query was correct the whole time. The log source it depended on was switched off. This whole flow was new to me and I learned my way around auditpol doing it, which was worth the detour on its own.

I turned it on and verified:

```
auditpol /set /subcategory:"Directory Service Access" /success:enable
auditpol /get /subcategory:"Directory Service Access"
```

![auditpol confirming Directory Service Access now set to Success](images/06-ds-access-auditing-on.png)

There is a second half to this that tripped me up, and it is easy to miss. The audit subcategory is the master switch, but the directory object itself also needs a SACL telling Windows which access rights to record. Without it, I could enable auditing, rerun the attack, and still get nothing. So I set the SACL on the domain object. In ADSI Edit, connected to the Default naming context, I opened the properties of the domain root object (`DC=condef,DC=local`), went to Security, Advanced, the Auditing tab, and added an entry: principal Everyone, type Success, applies to this object and all descendant objects, with Replicating Directory Changes and Replicating Directory Changes All checked. Those two rights are near the bottom of a long permissions list, so they are easy to scroll past.

With auditing on and the SACL in place, I reran the DCSync from win11a and ran the query again.

![Detection query now returning the DCSync event](images/07-4662-detection-result.png)

This time it caught the DCSync. The row shows `CONDEF\Administrator` targeted, object `DC=condef,DC=local`, right `Replicating Directory Changes All`, status success. The detection worked.

### The enrichment half exposed something interesting

The query does two jobs. The first block is the detection: the 4662 plus the replication GUID. The second block is enrichment, a left join to 4624 logon events meant to pull in the source IP, port, and authentication package behind the replication. That is what the `IsDC` field is built on, since replication from a host that is not a DC is the suspicious condition.

But the `IsDC` column came back reading **"No source IP in 4624 (Kerberos logon)."** That is the finding. The logon behind this DCSync authenticated over Kerberos, and Kerberos 4624 events often log a blank IpAddress, because the address lives in the Kerberos ticket exchange rather than the logon event. So the detection succeeded, but the source IP I wanted to attribute the attacker was not in the 4624. I built that explicit branch into the `case` statement on purpose so the gap shows up in the table instead of leaving a blank I would have to puzzle over later.

## Recovering the source IP (Event 4769)

Since the 4624 could not attribute the attacker, I went to the Kerberos service-ticket events. 4769 (TGS-REQ) is logged on the DC and it does record the requesting client's address.

```spl
index=winlogs EventCode=4769 TargetUserName="Administrator*"
| eval src_ip = replace(IpAddress, "^::ffff:", "")
| table _time, TargetUserName, ServiceName, src_ip, TicketEncryptionType
```

![4769 query showing source IP 192.168.137.138 across all events](images/08-4769-source-ip-recovery.png)

One thing that cost me a few minutes: my first attempt used the field names from the Windows event viewer (`Account_Name`, `Service_Name`, `Client_Address`) and returned zero results even though the events were there. Splunk's TA parses them as `TargetUserName`, `ServiceName`, and `IpAddress`. I had to read the raw event to find the real names. Lesson filed away: confirm field names against the raw event, do not trust the display labels.

The address also comes through IPv6-mapped, like `::ffff:192.168.137.138`, so I strip the `::ffff:` prefix with `replace` to get a clean IPv4.

The result gave me the source: `192.168.137.138`, which is win11a, consistent across all 11 events. The ServiceName column traces the whole Kerberos sequence leading into the attack: `krbtgt` (getting the ticket-granting ticket), `DC$` (requesting a ticket to authenticate to the DC), and `WIN11A$`, the machine account, which names the origin host directly. One `::1` row is the DC talking to itself and I ignored it. So the source IP the 4624 could not give me was fully recovered from 4769.

The `TicketEncryptionType` is `0x12` throughout, which is AES256. That is the normal ticket type here and not suspicious. I note it only because a downgrade to `0x17` (RC4) on this same event would point at Kerberoasting, a different attack.

Only domain controllers should be doing replication, so win11a doing it is the anomaly, and now I can name the host that did it.

## Confirming it on the network (Malcolm / Zeek / Arkime)

I wanted to see the same attack on the wire, so I switched to my Malcolm box, which had been capturing the whole time, and searched Arkime:

```
zeek.notice.msg == drsuapi::DRSGetNCChanges
```

![Arkime session and Zeek notice classifying the DCSync as T1003.006](images/09-arkime-drsuapi-notice.png)

That returned one session, and it is the DCSync. DCSync rides over Microsoft RPC on the DRSUAPI interface, and the specific call that pulls the account data is `DRSGetNCChanges`. That call is the network equivalent of the 4662 I detected on the DC.

What makes this result strong is that Malcolm's Zeek layer did not just show me raw RPC and leave me to interpret it. It classified the session. The Zeek notice.log fields name it outright: Notice Type `ATTACK::Credential_Access`, Message `drsuapi::DRSGetNCChanges`, and a submessage of `T1003.006 OS Credential Dumping: DCSync`. The session is tagged Event Category ATTACK with a risk score of 80. So the network sensor identified the technique and even the ATT&CK ID on its own, which is a nice contrast to the Splunk side where I built the detection logic myself.

The part that ties it all together is the source and destination. The notice shows `192.168.137.138` (win11a) reaching `192.168.137.135` (the DC) on port 49668, a dynamic high port, which is the normal DCE/RPC handoff after the endpoint mapper on 135. That win11a to DC path is the exact same one I attributed through the 4769 Kerberos events.

So I have the attack confirmed from two independent angles. The Windows host logs on the DC caught the replication and let me trace it back to win11a. The network capture caught the same replication on the wire and classified it as DCSync without relying on the DC's logging at all. Two sensors, two layers, one attack, and neither depends on the other.

## Key takeaways

- **A detection is only as good as the log source under it.** My 4662 query was correct from the first run and still returned nothing, because Directory Service Access auditing was off. Before trusting a quiet detection, verify the source is actually generating the event.
- **Two switches, not one.** 4662 for DCSync needs both the audit subcategory enabled and a SACL on the domain object for the replication rights. Turning on one without the other still leaves you blind.
- **Separate the core detection from the enrichment.** The 4662 plus replication-GUID signal stands on its own. The 4624 join is a nice-to-have that failed here, and I did not want the detection to depend on it.
- **Kerberos logons hide the source IP.** 4624 often logs a blank address for Kerberos, so for DCSync attribution I leaned on 4769, which carries the client IP. The network capture confirmed it.
- **The primitive is host-independent.** Whatever tool performs DCSync, it has to make a replication request, and only a DC should. That single observable, on the host log and on the wire, is what the whole detection rests on.

## References

- MITRE ATT&CK T1003.006: https://attack.mitre.org/techniques/T1003/006/
- Microsoft, Event 4662: https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4662
- NVISO, Detecting DCSync and DCShadow network traffic: https://blog.nviso.eu/2021/11/15/detecting-dcsync-and-dcshadow-network-traffic/
