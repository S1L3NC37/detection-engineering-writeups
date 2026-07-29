# Catching DCSync: Detecting Domain Replication Abuse

**Lab:** `condef.local` · **Platform:** Windows / Active Directory · **Log sources:** Windows Security (4662, 4769), Zeek/Arkime network capture · **SIEM:** Splunk · **ATT&CK:** T1003.006 (OS Credential Dumping: DCSync) · **Tactic:** Credential Access

## TL;DR

DCSync abuses the same Active Directory replication functionality that domain controllers use to synchronize directory data. An attacker with the required replication permissions can request password material from a domain controller without accessing `ntds.dit` directly or dumping LSASS memory on the DC.

I ran DCSync from a Windows 11 workstation and detected the use of directory replication rights in Windows Event 4662. My first attempt returned no results because the domain controller was not configured to generate the required event. After enabling Directory Service Access auditing and configuring a SACL on the domain object, the detection succeeded.

The 4662 result identified the account performing the replication operation but did not provide usable source-host information through my 4624 enrichment. I investigated Event 4769 to recover the client IP, then independently confirmed the workstation-to-DC replication traffic through Malcolm, Zeek, and Arkime.

## What DCSync is

Active Directory uses replication to keep domain controllers synchronized. During legitimate replication, one domain controller requests directory changes from another.

DCSync abuses that functionality. Instead of reading credentials from process memory, the attacker sends a replication request to a domain controller and asks it to return password data for an account. The request succeeds when the account being used has the necessary directory replication rights.

I performed the attack with Mimikatz using an account that already had those privileges. DCSync can retrieve high-value credential material such as NTLM hashes and Kerberos keys without executing credential-dumping code directly on the domain controller.

The impact depends on which account is requested. Retrieving the built-in Administrator account provides reusable privileged credential material. Retrieving the `krbtgt` account would expose the key material used to create Golden Tickets.

## Running the attack

I ran the attack from `win11a` against the domain controller:

```text
lsadump::dcsync /domain:condef.local /user:Administrator
```

![Mimikatz DCSync output showing the Administrator NTLM hash and Kerberos keys](images/01-mimikatz-dcsync-output.png)

Mimikatz requested the credential material for the built-in Administrator account. The output included:

* **NTLM hash** (`64f12c...`): reusable authentication material that can support pass-the-hash.
* **AES256 and AES128 Kerberos keys**: reusable Kerberos authentication material.
* **Password last change: 7/2/2026**: the date associated with the retrieved password material.
* **Object Relative ID: 500**: confirms that the requested account was the built-in domain Administrator.

This was not a Golden Ticket test. Golden Ticket creation requires the key or password hash of the domain’s `krbtgt` account. In this run, I specifically requested the Administrator account.

## Detecting replication-right use with Event 4662

The first Windows event I investigated was Event 4662, **“An operation was performed on an object.”**

For DCSync detection, the important data appears in the event’s `Properties` field. The replication rights include:

* `1131f6ac-9c07-11d1-f79f-00c04fc2dcd2`: DS-Replication-Get-Changes
* `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`: DS-Replication-Get-Changes-All
* `9923a32a-3607-11d2-b9be-0000f87a36b2`: DS-Replication-Get-Changes-In-Filtered-Set

I used a domain administrator account for the test, so the account already possessed the permissions needed to make the replication request.

This was the Splunk query I used. It searches for Event 4662 records involving the domain object and replication rights, then attempts to enrich the result with Event 4624 logon context:

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

### It returned nothing

I ran the query immediately after the attack and received no results.

![Full detection query returning zero results](images/02-detection-query-zero-results.png)

I stripped the search down to the event code to determine whether Event 4662 was present at all:

```spl
index=winlogs EventCode=4662
```

![Bare 4662 search also returning zero results](images/03-bare-4662-zero-results.png)

That search also returned nothing.

At that point, either the Windows event pipeline was not working or the domain controller was not generating Event 4662. I checked the entire index:

```spl
index=winlogs
```

![winlogs index populated with 634 events from host DC](images/04-winlogs-pipeline-healthy.png)

Splunk returned 634 events with the `XmlWinEventLog:Security` sourcetype from host `DC`. Windows Security events were reaching Splunk, so the absence of Event 4662 was not caused by a general forwarding failure.

The domain controller was not generating the event.

## Enabling Directory Service Access auditing

Event 4662 depends on the **Directory Service Access** audit subcategory. I checked its status on the domain controller:

```powershell
auditpol /get /subcategory:"Directory Service Access"
```

![auditpol showing Directory Service Access set to No Auditing](images/05-ds-access-auditing-off.png)

The result was **No Auditing**.

This explained why the attack had not produced Event 4662. The underlying activity occurred, but the Windows auditing configuration required by the detection was disabled.

I enabled successful Directory Service Access auditing and verified the result:

```powershell
auditpol /set /subcategory:"Directory Service Access" /success:enable
auditpol /get /subcategory:"Directory Service Access"
```

![auditpol confirming Directory Service Access now set to Success](images/06-ds-access-auditing-on.png)

Enabling the audit subcategory was only the first requirement.

Event 4662 is generated when the performed operation matches an auditing entry in the target object’s system access control list, or SACL. Without the appropriate SACL on the Active Directory object, enabling the audit policy alone still did not produce the event I needed.

In ADSI Edit, I connected to the **Default naming context** and opened the domain root object:

```text
DC=condef,DC=local
```

Under **Security > Advanced > Auditing**, I added a successful auditing entry for the `Everyone` principal that applied to the object and its descendants. I selected:

* Replicating Directory Changes
* Replicating Directory Changes All

With both the audit subcategory and the SACL configured, I reran DCSync from `win11a`.

## Successful Event 4662 detection

I ran the Splunk query again after repeating the attack:

![Detection query now returning the DCSync event](images/07-4662-detection-result.png)

This time, the query returned an Event 4662 result.

The event showed:

* **Subject account:** `CONDEF\Administrator`
* **Object:** `DC=condef,DC=local`
* **Property:** `Replicating Directory Changes All`
* **Status:** Success

The Subject fields identify the account that performed the directory operation. They do not identify the account whose credential material was requested.

In this test, `CONDEF\Administrator` was both the account I used to execute DCSync and the account I requested from the domain controller. The Event 4662 record confirms that Administrator performed a successful replication-right operation against the domain object. The Mimikatz output separately confirms that the requested credential target was Administrator.

## The 4624 enrichment did not provide a source

The first portion of my Splunk search identifies the Event 4662 replication operation. The second portion attempts to join the event to an Event 4624 logon using the computer and logon ID.

I intended to use the joined 4624 fields to retrieve:

* Logon time
* Authentication package
* Source IP
* Source port

Those fields would then feed the `IsDC` calculation.

The result displayed:

```text
No source IP in 4624 (Kerberos logon)
```

That text was generated by my own `case` statement whenever `src_ip` was null or blank. It was not a value recorded directly by Windows.

The other joined fields, including `LogonTime`, `AuthenticationPackageName`, `src_ip`, and `IpPort`, were also blank. From this output alone, I could not determine whether the join found a matching 4624 event with no IP address or failed to find a usable matching 4624 event at all.

The core Event 4662 detection still succeeded, but the enrichment did not provide enough information to identify the originating system.

## Recovering the source IP with Event 4769

Because the 4624 enrichment did not return usable source information, I investigated Event 4769, **“A Kerberos service ticket was requested.”**

Event 4769 includes the client address associated with the service-ticket request. I searched for requests involving the Administrator account:

```spl
index=winlogs EventCode=4769 TargetUserName="Administrator*"
| eval src_ip = replace(IpAddress, "^::ffff:", "")
| table _time, TargetUserName, ServiceName, src_ip, TicketEncryptionType
```

![4769 query showing source IP 192.168.137.138 across all events](images/08-4769-source-ip-recovery.png)

My first version of the search used the Windows Event Viewer display labels:

* `Account_Name`
* `Service_Name`
* `Client_Address`

Those field names returned no results. After inspecting the raw event in Splunk, I found that the Splunk Technology Add-on had parsed the fields as:

* `TargetUserName`
* `ServiceName`
* `IpAddress`

After correcting the field names, the search returned the events.

The IP addresses appeared in IPv6-mapped IPv4 format:

```text
::ffff:192.168.137.138
```

I used `replace` to remove the `::ffff:` prefix.

The client address was consistently:

```text
192.168.137.138
```

That address belongs to `win11a`, the workstation from which I ran Mimikatz.

The `ServiceName` values included `krbtgt`, `DC$`, and `WIN11A$`. In Event 4769, `ServiceName` identifies the service account for which a ticket was requested. It does not identify the requesting computer. The `src_ip` field was the evidence that identified `win11a` as the client.

One result used the loopback address `::1`, indicating local activity on the domain controller. The remaining results consistently identified `192.168.137.138`.

The ticket encryption type was `0x12`, or AES256. I recorded that as additional context, but it was not part of my DCSync detection condition.

The Event 4769 investigation gave me the source information that the 4624 enrichment did not provide.

## Confirming DCSync on the network

I then checked the network capture in Malcolm and searched Arkime for the DRSUAPI operation associated with the attack:

```text
zeek.notice.msg == drsuapi::DRSGetNCChanges
```

![Arkime session and Zeek notice classifying the DCSync as T1003.006](images/09-arkime-drsuapi-notice.png)

The search returned one matching session.

DCSync uses Microsoft’s Directory Replication Service Remote Protocol. The `DRSGetNCChanges` operation requests directory replication data from a domain controller.

The Zeek notice classified the session with:

* **Notice Type:** `ATTACK::Credential_Access`
* **Message:** `drsuapi::DRSGetNCChanges`
* **Submessage:** `T1003.006 OS Credential Dumping: DCSync`
* **Event Category:** `ATTACK`
* **Risk score:** `80`

The network session showed:

* **Source:** `192.168.137.138` (`win11a`)
* **Destination:** `192.168.137.135` (`DC`)
* **Destination port:** `49668`

The source and destination matched the systems involved in my test. The client IP also matched the address recovered through the Event 4769 investigation.

This provided an independent network-level confirmation of the replication request. The Windows telemetry recorded use of the replication right on the domain controller, while Malcolm identified the corresponding `DRSGetNCChanges` communication from the workstation to the DC.

## What the evidence established

The different data sources answered different parts of the investigation:

| Evidence                | What it established                                                                                 |
| ----------------------- | --------------------------------------------------------------------------------------------------- |
| Mimikatz output         | Administrator credential material was successfully requested                                        |
| Event 4662              | `CONDEF\Administrator` performed a successful replication-right operation against the domain object |
| Event 4769              | Kerberos service-ticket requests associated with Administrator came from `192.168.137.138`          |
| Malcolm / Zeek / Arkime | `192.168.137.138` sent a `DRSGetNCChanges` request to the domain controller                         |
| Lab inventory           | `192.168.137.138` was `win11a`, not a domain controller                                             |

Event 4662 alone did not identify the credential target or provide a usable source IP through my enrichment. The Mimikatz output established the requested account, and the Kerberos and network telemetry established the originating workstation.

## Key takeaways

* **A detection depends on its telemetry.** My initial search returned nothing because the domain controller was not generating Event 4662. Verifying the underlying event source prevented me from treating missing telemetry as a clean result.

* **Event 4662 required two auditing components.** I needed both successful Directory Service Access auditing and a SACL on the domain object covering the replication rights.

* **The Event 4662 subject is the actor, not the credential target.** The event showed that `CONDEF\Administrator` performed the replication operation. The Mimikatz output showed that Administrator was also the account requested during this specific test.

* **The core detection and the enrichment produced different results.** The replication-right search succeeded, but the 4624 join did not return usable source context.

* **A calculated label is not raw evidence.** The `IsDC` value came from my SPL logic. Because the joined fields were blank, the label could not prove why the source IP was missing.

* **Event 4769 provided client attribution.** Its client address consistently identified `192.168.137.138`, while `ServiceName` identified the requested Kerberos service rather than the originating host.

* **Network telemetry independently confirmed the activity.** Malcolm observed `DRSGetNCChanges` from `win11a` to the domain controller and classified it as DCSync.

* **The suspicious condition was established through correlation.** In this lab, directory replication originated from a known workstation rather than the only domain controller. Windows and network evidence both pointed to the same source.

## References

* MITRE ATT&CK, T1003.006: https://attack.mitre.org/techniques/T1003/006/
* MITRE ATT&CK, T1558.001 Golden Ticket: https://attack.mitre.org/techniques/T1558/001/
* Microsoft, Event 4662: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662
* Microsoft, Event 4769: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769
* NVISO, Detecting DCSync and DCShadow Network Traffic: https://blog.nviso.eu/2021/11/15/detecting-dcsync-and-dcshadow-network-traffic/
