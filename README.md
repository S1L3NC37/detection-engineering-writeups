# Detection Engineering Lab

I built a fully monitored environment from scratch and I write detections against it, mapped to MITRE ATT&CK, across Windows and Active Directory, Linux, Kubernetes, and cloud (Entra ID and AWS).

Each detection writeup follows the same shape: run the technique in the lab, find the telemetry it produced, work out the signal that separates it from normal activity, and then tune it against the false positives that signal drags in. The queries are the easy part. The reasoning behind them is what I am actually practicing.

**Status:** the lab build is complete and written up. Detection writeups are published one at a time as I finish them.

> **Safety:** this is an isolated lab on a NAT'd subnet. All credentials are throwaway values and all cloud resources use disposable accounts. Nothing here is production.

---

## Writeups

**[Building a Detection Lab on One Machine](building-a-detection-lab-on-one-machine.md)**
How the environment is put together and why. The network, the domain, endpoint telemetry, the collection tier, the cloud and Kubernetes pipelines, what the RAM constraint forced me to decide, and the failures that taught me the most.

Detection writeups start next, beginning with execution on Windows: `cmd.exe` spawned by a non-Explorer parent, and anomalous command-line length. Each one gets added here as it lands, with its ATT&CK mapping and the false positives I had to tune out.

---

## Lab architecture

![Detection lab architecture](images/lab-topology.png)

**Domain:** `condef.local` · **Network:** VMware NAT `192.168.137.0/24` (gateway `.2`)

| Host | Address | Role |
|---|---|---|
| DC | `192.168.137.135` | Windows Server 2019: domain controller, DNS, **Splunk Enterprise 9.3.2** |
| CERTER | `192.168.137.136` | Member server, Sysmon config-push host |
| Win11V | `192.168.137.137` | Domain-joined workstation (Sysmon), primary detonation target |
| Win11A | `192.168.137.138` | Domain-joined workstation (Sysmon) |
| LinuxA | `192.168.137.139` | Attacker box: Metasploit, later Mythic C2 |
| Malcolm | `192.168.137.140` | Network traffic analysis appliance |
| LinuxV | `192.168.137.141` | Minikube / Kubernetes host, auditd and Laurel telemetry |

Every VM runs on one physical host with 32 GB of RAM. Their combined minimum allocation is closer to 44 GB, so they cannot all run at once. Deciding which of them coexist turned out to be the most instructive constraint in the whole build.


### Telemetry pipeline

Host and cloud telemetry lands in Splunk across purpose-built indexes. Network traffic is analyzed separately in Malcolm, and detections correlate across both.

| Index | Source |
|---|---|
| `winlogs` | Windows Security and System event logs |
| `sysmon` | Sysmon (sysmon-modular config) |
| `etw` | ETW providers (index created, not yet fed) |
| `linux` | auditd via Laurel |
| `kube` | Kubernetes audit logs via OTel collector |
| `azure` | Entra ID sign-in and audit logs via Event Hub |
| `aws` | CloudTrail via S3 |

**Ingest routes:** Universal Forwarder push on `9997`, HTTP Event Collector push on `8088`, S3 pull for AWS, Event Hub consume for Azure. Two push, two pull, with different failure modes each. Malcolm captures off the virtual network in promiscuous mode.

### Tooling

Splunk Enterprise 9.3.2 · Splunk Universal Forwarder · Splunk Add-on for AWS · Splunk Add-on for Microsoft Cloud Services · Splunk OpenTelemetry Collector · Malcolm · Sysmon + [sysmon-modular](https://github.com/olafhartong/sysmon-modular) · Laurel + auditd ([Neo23x0 ruleset](https://github.com/Neo23x0/auditd)) · Minikube + kubectl + Helm · Azure Event Hubs + Entra ID diagnostic settings · AWS CloudTrail + S3

---

## Background

I built this lab while working through [Constructing Defense](https://justhacking.com) by Anton Ovrutsky (justhacking.com). I took the Lite track, which means no provided cyber range: I stood up the entire environment myself, on my own hardware.

I followed the course's guidance for the lab architecture and the telemetry configuration. What I own is everything between the instruction and the working system: standing it up under a RAM constraint the guidance doesn't account for, diagnosing what broke, and understanding why each piece is there rather than just that it worked. The detection writeups run against my own environment, so the thresholds I picked and the false positives I had to tune out came from my data, not from a worked example.
