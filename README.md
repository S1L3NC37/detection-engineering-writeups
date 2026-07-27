# Detection Engineering Portfolio

This repository documents my hands-on detection engineering work in a lab I built and operate on my own hardware.

For each detection, I execute an attack technique, identify the telemetry it produces, develop Splunk detection logic, compare the malicious activity against normal behavior, and document the resulting false positives, limitations, and investigation considerations.

The queries are only the final output. The primary focus of this portfolio is the reasoning used to move from attacker behavior to a testable detection hypothesis.

> **Detection status:** The detections in this repository are validated in my isolated lab. They have not been tested in a production environment and may require additional baselining and tuning before operational use.

> **Safety:** The environment runs on an isolated VMware NAT network. All credentials are throwaway values, and all cloud resources use disposable lab accounts.

---

## What This Portfolio Demonstrates

* Building and operating a multi-source detection lab
* Translating attacker behavior into observable telemetry
* Developing and iteratively refining SPL detections
* Identifying logging and audit-policy dependencies
* Baselining normal behavior and investigating false positives
* Testing related attack procedures against the same telemetry
* Correlating Windows host telemetry with network evidence
* Documenting detection limitations, blind spots, and analyst response considerations
* Mapping detection coverage to MITRE ATT&CK

---

## Writeups

### [Building a Detection Lab on One Machine](building-a-detection-lab-on-one-machine.md)

How I built the environment and why each component is present. This writeup covers the network, Active Directory domain, endpoint telemetry, Splunk collection tier, Malcolm network monitoring, Linux and Kubernetes logging, cloud pipelines, resource constraints, and the failures that taught me the most during the build.

### [Catching My First Reverse Shell](catching-my-first-reverse-shell.md)

I executed a Meterpreter reverse shell against a Windows workstation and developed two Splunk detections from different behavioral signals: the process relationship that produced the shell and the abnormal length of the command line used to launch it.

The writeup covers why each signal works in my environment, the false positives each approach introduces, the effect of environmental allowlisting, and why combining multiple imperfect signals can provide stronger coverage than relying on either signal alone.

### [Catching LSASS Credential Dumping Three Ways](catching-lsass-credential-dumping.md)

I dumped LSASS using three procedures: Mimikatz through Meterpreter, Task Manager, and Procdump. I then developed complementary Sysmon detections for suspicious access to `lsass.exe` and the creation of LSASS dump files.

The writeup examines the `GrantedAccess` bitmask and why the `PROCESS_VM_READ` right is an important signal, how legitimate processes can request similar access, and how environmental baselining reduces noise. It also explains why covering all three tested procedures requires both ProcessAccess and FileCreate telemetry, along with the false positives and blind spots introduced by each approach.

### [Catching Credential Access Through File Shares](catching-credential-access-through-file-shares.md)

I created Windows file shares, planted a simulated sensitive file named `passwords.txt`, and used Snaffler to crawl the environment. I then developed two Splunk detections using Windows Security Event 5145: one for access to potentially sensitive filenames and another for unusually high failure volume associated with share discovery activity.

The writeup covers the fields used to develop the detections, the audit policy required to generate the telemetry, threshold-related false positives, and how Malcolm network telemetry independently corroborated the same SMB activity.

### [Catching Kerberoasting](catching-kerberoasting.md)

I created Active Directory service accounts with Service Principal Names and used Impacket's `GetUserSPNs` to request crackable Kerberos service tickets. I investigated the resulting Windows Security Event 4769 telemetry and developed a Splunk detection based on one account requesting multiple service tickets within a short period.

The writeup compares encryption-type and request-volume signals, examines the same Kerberoasting activity through Malcolm network telemetry, and completes the exercise by cracking a captured service ticket in the lab.

---

## Detection Catalog

| Detection                                                                                        | Platform | Telemetry         | MITRE ATT&CK                                                                       | Status        |
| ------------------------------------------------------------------------------------------------ | -------- | ----------------- | ---------------------------------------------------------------------------------- | ------------- |
| [Reverse shell: anomalous process relationship](catching-my-first-reverse-shell.md)              | Windows  | Sysmon EID 1      | [T1059.003: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003/) | Lab validated |
| [Reverse shell: abnormal command-line length](catching-my-first-reverse-shell.md)                | Windows  | Sysmon EID 1      | [T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001/)            | Lab validated |
| [LSASS access by GrantedAccess rights](catching-lsass-credential-dumping.md)                     | Windows  | Sysmon EID 10     | [T1003.001: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)          | Lab validated |
| [LSASS dump-file creation](catching-lsass-credential-dumping.md)                                 | Windows  | Sysmon EID 11     | [T1003.001: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)          | Lab validated |
| [Potentially sensitive file access on shares](catching-credential-access-through-file-shares.md) | Windows  | Security EID 5145 | [T1552.001: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)  | Lab validated |
| [Share discovery by failure volume](catching-credential-access-through-file-shares.md)           | Windows  | Security EID 5145 | [T1135: Network Share Discovery](https://attack.mitre.org/techniques/T1135/)       | Lab validated |
| [Kerberoasting by service-ticket request volume](catching-kerberoasting.md)                      | Windows  | Security EID 4769 | [T1558.003: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)         | Lab validated |

Additional detections will be added to the catalog as their investigation and validation writeups are completed.

---

## Lab Architecture

![Detection lab topology showing the Windows domain, attacker system, Splunk, Malcolm, Kubernetes, Entra ID, and AWS telemetry paths](images/lab-topology.png)

**Domain:** `condef.local`
**Network:** VMware NAT `192.168.137.0/24`
**Gateway:** `192.168.137.2`

| Host    | Address           | Role                                                                           |
| ------- | ----------------- | ------------------------------------------------------------------------------ |
| DC      | `192.168.137.135` | Windows Server 2019 domain controller, DNS server, and Splunk Enterprise 9.3.2 |
| CERTER  | `192.168.137.136` | Domain member server and Sysmon configuration-push host                        |
| Win11V  | `192.168.137.137` | Domain-joined Windows workstation, Sysmon endpoint, and primary attack target  |
| Win11A  | `192.168.137.138` | Domain-joined Windows workstation with Sysmon                                  |
| LinuxA  | `192.168.137.139` | Attacker system running Metasploit and later Mythic C2                         |
| Malcolm | `192.168.137.140` | Network traffic analysis appliance                                             |
| LinuxV  | `192.168.137.141` | Linux, Minikube, Kubernetes, auditd, and Laurel telemetry host                 |

Every virtual machine runs on one physical computer with 32 GB of RAM. Their combined minimum memory allocation is approximately 44 GB, so they cannot all operate simultaneously. Deciding which systems needed to run together became an important part of designing and troubleshooting the environment.

`LinuxA` is intentionally left uninstrumented and does not forward logs to Splunk. The detections must therefore rely on telemetry produced by the targeted systems and the surrounding network rather than information collected from the attacker system.

---

## Telemetry Pipeline

Host and cloud telemetry is collected in Splunk using purpose-built indexes. Network traffic is analyzed separately in Malcolm so activity can be examined from both endpoint and network perspectives.

| Splunk index | Data source                                               | Collection status                |
| ------------ | --------------------------------------------------------- | -------------------------------- |
| `winlogs`    | Windows Security and System event logs                    | Active                           |
| `sysmon`     | Sysmon using the sysmon-modular configuration             | Active                           |
| `etw`        | Event Tracing for Windows providers                       | Index created; not yet populated |
| `linux`      | Linux auditd events processed by Laurel                   | Active                           |
| `kube`       | Kubernetes audit logs through the OpenTelemetry Collector | Active                           |
| `azure`      | Entra ID sign-in and audit logs through Azure Event Hubs  | Active                           |
| `aws`        | AWS CloudTrail logs through Amazon S3                     | Active                           |

The currently published detection writeups focus on Windows and Active Directory telemetry. The wider lab also collects Linux, Kubernetes, Entra ID, and AWS data, but writeups for those platforms are not yet published.

### Ingestion Routes

* Splunk Universal Forwarder traffic is pushed to Splunk on TCP port `9997`.
* HTTP Event Collector traffic is pushed on TCP port `8088`.
* AWS CloudTrail data is pulled from Amazon S3.
* Entra ID events are consumed from Azure Event Hubs.
* Malcolm observes the virtual network in promiscuous mode.

These routes include both push- and pull-based collection methods, each with different configuration requirements and failure modes.

---

## Tooling

* Splunk Enterprise 9.3.2
* Splunk Universal Forwarder
* Splunk Add-on for AWS
* Splunk Add-on for Microsoft Cloud Services
* Splunk OpenTelemetry Collector
* Malcolm
* Sysmon with [sysmon-modular](https://github.com/olafhartong/sysmon-modular)
* Laurel and auditd with the [Neo23x0 auditd ruleset](https://github.com/Neo23x0/auditd)
* VMware Workstation
* Windows Server 2019
* Windows 11
* Active Directory Domain Services
* Metasploit Framework
* Impacket
* Minikube
* Kubernetes
* kubectl
* Helm
* Azure Event Hubs
* Microsoft Entra ID diagnostic settings
* AWS CloudTrail
* Amazon S3

---

## Background and Attribution

I built this lab while working through [Constructing Defense](https://www.justhacking.com/course/condef-lite/) by Anton Ovrutsky of justhacking.com.

I am completing the Lite track, which does not provide a hosted cyber range. I built the environment on my own hardware by following the course's architectural and telemetry guidance.

The course provides the overall learning path and technical direction. My work includes deploying the environment under its hardware constraints, diagnosing collection and configuration failures, executing the techniques, analyzing the telemetry produced in my lab, developing the SPL queries, investigating false positives, and documenting the results.

Because the detections are developed against my own environment, the observed baselines, thresholds, exclusions, and limitations are specific to this lab rather than production recommendations.

---

## Repository Purpose

This is an ongoing learning and portfolio repository. Its purpose is to demonstrate how I approach detection engineering problems, including the unsuccessful searches, telemetry gaps, tuning decisions, and limitations that occur between an attack technique and a usable detection.

The work is intended for educational and defensive security purposes.
