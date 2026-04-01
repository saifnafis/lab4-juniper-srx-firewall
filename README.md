# Lab 4 — Enterprise Firewall Policy Configuration on Juniper SRX

**Subject:** 48730/32548 Cybersecurity — University of Technology Sydney  
**Tools Used:** Juniper SRX (JunOS CLI), iptables (Linux)  
**Skills Demonstrated:** Enterprise firewall policy design, zone-based security, application-layer filtering, firewall user authentication, Linux iptables hardening

---

## Overview

This lab covers the configuration of security policies on a Juniper SRX firewall — the same class of enterprise-grade equipment deployed in corporate networks, data centres, and government environments across Australia. The work covers zone-based policy design, application-specific traffic control, and pass-through firewall authentication. A Linux iptables challenge is also included, demonstrating the same concepts applied to host-based firewalling.

Understanding how to write, read, and troubleshoot firewall policies is a fundamental skill for network security engineers and SOC analysts. A poorly written policy is often the direct cause of a security incident.

---

## Background: Zone-Based Firewalling

Unlike traditional stateless ACLs that filter by IP and port alone, the Juniper SRX uses a **zone-based security model**. Traffic is evaluated based on which security zone it originates from and which zone it is destined for. Each zone-pair can have its own set of named policies with fine-grained match conditions and actions.

The lab environment had two zones pre-configured:
- **Internet** — the untrusted external zone
- **Internal** — the trusted internal network zone

By default, the initial configuration had a blanket `permit any` policy in both directions, which is appropriate for a clean-slate lab environment but completely inappropriate in production — it allows all traffic in and out with no restrictions whatsoever.

---

## Task 1 — Analysing the Default Permissive Policy

### Initial state observed

```
from-zone Internet to-zone Internal {
    policy All_Internet_Internal {
        match {
            source-address any;
            destination-address any;
            application any;
        }
        then {
            permit;
        }
    }
}
from-zone Internal to-zone Internet {
    policy All_Internal_Internet {
        match {
            source-address any;
            destination-address any;
            application any;
        }
        then {
            permit;
        }
    }
}
```

### What this means
Both policies use `source-address any`, `destination-address any`, and `application any` — meaning every packet from every source to every destination using any protocol is permitted. This is effectively no firewall at all. In a real deployment this would be a critical finding in any security audit.

The `any` application matcher bypasses Junos application inspection, meaning the firewall is not checking whether traffic on a given port actually matches the expected protocol. An attacker could run a command-and-control channel on port 80 and the firewall would not flag it.

---

## Task 2 — Configuring a Restrictive FTP Policy

### What I did
Replaced the open `any-any-any` policy with a specific policy that permits only FTP traffic in both directions, using the JunOS built-in application object `junos-ftp`.

### Configuration applied

```
from-zone Internet to-zone Internal {
    policy Saif {
        match {
            source-address any;
            destination-address any;
            application junos-ftp;
        }
        then {
            permit;
        }
    }
}
```

A matching policy was created for outbound FTP (Internal to Internet) with the same match criteria.

### Why using `junos-ftp` matters
Using the named application object `junos-ftp` rather than manually specifying port 21 is significant. Junos application objects include deep packet inspection logic — `junos-ftp` understands the FTP protocol structure, including the passive mode data channel negotiation that opens dynamic secondary ports. A simple port-21 ACL rule would break passive FTP. Using the application object handles this correctly.

---

## Task 3 (Challenge) — Rejecting Telnet Traffic

### What I did
Added a second policy specifically targeting Telnet (`junos-telnet`) with a `reject` action rather than `permit`, while leaving the FTP policy intact.

### Key distinction: deny vs reject

This is an important operational difference:
- **Deny:** Silently drops the packet. The sender receives no response and must wait for a timeout.
- **Reject:** Drops the packet and sends back an ICMP Port Unreachable message (for UDP) or a TCP RST (for TCP), immediately notifying the sender that the connection was refused.

For Telnet, `reject` was used because it provides faster feedback to administrators troubleshooting connectivity, and it is more honest in an internal network where there is less concern about revealing port status to attackers. In an internet-facing context, `deny` is often preferred to avoid giving attackers information about what is or is not running.

### Final policy state

```
policy Saif {
    match {
        source-address any;
        destination-address any;
        application [ junos-ftp junos-telnet ];
    }
    then {
        reject;
    }
}
```

This combined policy matches both FTP and Telnet traffic and rejects it — demonstrating how multiple applications can be grouped in a single match condition.

---

## Linux Challenge — iptables: HTTP/HTTPS Only Firewall

### What I did
Hardened a Linux server using iptables to enforce a default-deny policy, then explicitly permitted only HTTP (port 80) and HTTPS (port 443) traffic.

### Commands used

```bash
# Set default DROP policy on all chains
sudo iptables --policy INPUT DROP
sudo iptables --policy OUTPUT DROP
sudo iptables --policy FORWARD DROP

# Allow incoming HTTP and HTTPS connections
sudo iptables -A INPUT  -p tcp --dport 80  -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 80  -m state --state ESTABLISHED     -j ACCEPT
sudo iptables -A INPUT  -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
```

### Why stateful matching matters
The `-m state --state NEW,ESTABLISHED` flags use iptables connection tracking. This means:
- Incoming rule only allows packets that are either starting a new connection (`NEW`) or part of an existing one (`ESTABLISHED`)
- The corresponding output rule only allows reply packets for connections that are already established

Without stateful matching, a simple `ACCEPT` rule on port 80 would also allow unsolicited inbound packets on that port from arbitrary sources. Stateful inspection ensures only legitimate bidirectional traffic flows through.

### Verified result (iptables -L)

```
Chain INPUT (policy DROP)
ACCEPT  tcp -- anywhere  anywhere  tcp dpt:http  state NEW,ESTABLISHED
ACCEPT  tcp -- anywhere  anywhere  tcp dpt:https state NEW,ESTABLISHED

Chain OUTPUT (policy DROP)
ACCEPT  tcp -- anywhere  anywhere  tcp spt:http  state ESTABLISHED
ACCEPT  tcp -- anywhere  anywhere  tcp spt:https state NEW,ESTABLISHED
```

All other traffic — SSH, Telnet, FTP, DNS, ICMP — is silently dropped by the default policy.

---

## Task — Juniper SRX Firewall User Authentication (Pass-Through)

### What I did
Configured pass-through firewall authentication on the Juniper SRX, requiring users to authenticate before accessing internal resources via Telnet. This involved three components working together:

1. **Access profile** — defines user credentials stored on the firewall
2. **Pass-through authentication** — intercepts the connection and challenges the user before allowing it through
3. **Security policy** — enforces authentication as a condition of the permit action

### Configuration applied

**Access profile:**
```
profile Saif {
    client Saif {
        firewall-user {
            password "$9$lxEKLx-VwgaZdVP5z39CLx7NYgik."; ## SECRET-DATA
        }
    }
}
```

**Pass-through authentication with success banner:**
```
pass-through {
    default-profile Saif;
    telnet {
        banner {
            success "Login successful!";
        }
    }
}
```

**Policy with authentication enforced:**
```
policy Saif {
    match {
        source-address any;
        destination-address any;
        application junos-telnet;
    }
    then {
        permit {
            firewall-authentication {
                pass-through {
                    client-match Saif;
                }
            }
        }
    }
}
```

### How pass-through authentication works
When a user initiates a Telnet session destined for the internal zone, the SRX intercepts the connection and presents an authentication challenge before forwarding the traffic. Only after successful credential validation against the access profile does the SRX permit the session to continue. The success banner `"Login successful!"` is then displayed.

This is a compensating control for legacy protocols like Telnet that have no built-in authentication at the application layer beyond the target host's own login prompt. Adding firewall-level authentication means even if an attacker reaches the Telnet port, they face an additional credential challenge at the network perimeter.

### Key benefit
Pass-through authentication links network access to individual user identities. Every session is tied to a named account, creating an audit trail that connects network activity to specific users — essential for compliance and incident investigation.

---

## Key Takeaways

Firewall policy is not just about allowing or blocking ports. Effective policy design requires understanding the protocols involved (why `junos-ftp` beats a port 21 rule), the operational implications of your choices (deny vs reject), stateful vs stateless filtering (why iptables connection tracking matters), and how to layer controls (combining zone policy with user authentication). A misconfigured firewall policy is one of the most common root causes of security incidents in enterprise environments.
