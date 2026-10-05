```

┌─────────────────────────────────────────────────────┐
│                 SCENARIO LAYER                      │
│                                                     │
│  normal_day.py   port_scan.py   brute_force.py      │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│              SME NETWORK SIMULATION                 │
│                                                     │
│ Internet                                             │
│    │                                                 │
│ Firewall                                             │
│    │                                                 │
│ Core Switch                                          │
│ ├─ VLAN10 Users                                      │
│ ├─ VLAN20 Servers                                    │
│ ├─ VLAN30 DMZ                                        │
│ ├─ VLAN40 Management                                 │
│ └─ VLAN50 Guest                                      │
└────────────────────────┬────────────────────────────┘
                         │ simulated traffic
                         ▼
┌─────────────────────────────────────────────────────┐
│               SECURITY SENSOR                       │
│                                                     │
│ Simulated Zeek     Simulated Suricata               │
│     │                    │                          │
│ metadata              alerts                        │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│                LOG PIPELINE                         │
│                                                     │
│ Endpoint logs │ Firewall logs │ IDS │ Network logs  │
└────────────────────────┬────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────┐
│                  SIMULATED SIEM                     │
│                                                     │
│ ingest → normalize → store → correlate → detect     │
│                    │                                │
│                    ▼                                │
│                Threat Hunting                       │
└─────────────────────────────────────────────────────┘

```