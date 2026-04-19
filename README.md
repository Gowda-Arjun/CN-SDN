# Dynamic Host Blocking System (Mininet + Ryu)

## Problem Statement
This project implements a dynamic host blocking mechanism in SDN.
The controller observes traffic behavior in real time, detects suspicious hosts,
installs blocking flow rules, verifies that those rules exist in the switch,
and logs all important events.



## Project Features
1. Suspicious traffic detection
- Packet rate threshold per host in a sliding window.
- Broadcast rate threshold per host in a sliding window.

2. Dynamic blocking
- On suspicious behavior, controller installs high-priority drop flow:
  - match: in_port + eth_src
  - action: drop
  - hard timeout: 60 seconds

3. Verification
- Controller periodically requests flow stats.
- Confirms block rule installation and logs `block_verified`.

4. Logging
- Structured JSON log lines in `logs/block_events.log`.
- Event types include:
  - `host_blocked`
  - `block_verified`
  - `host_unblocked`
  - `block_verification_retry`

## Repository Structure
- `controller/dynamic_host_blocking.py`: Ryu app with detection/blocking/verification logic
- `controller/run_controller.py`: launcher with Eventlet compatibility patch
- `topology/dynamic_topology.py`: Mininet topology (h1, h2, h3, h4 attacker, s1)
- `scripts/setup_env_arch.sh`: Arch environment setup
- `scripts/run_demo.sh`: run controller + topology
- `scripts/verify_blocking.sh`: verify flow rules and logs
- `logs/block_events.log`: controller event evidence (generated at runtime)

## Why `run_controller.py` is used
On modern Eventlet versions, `eventlet.wsgi.ALREADY_HANDLED` is removed.
Ryu 4.34 still expects it. The launcher patches this symbol before importing
`ryu.cmd.manager`, allowing stable runtime on Arch + Python 3.10.

## Setup (Arch Linux)
```bash
chmod +x scripts/*.sh
./scripts/setup_env_arch.sh
```

## Run Demo
```bash
./scripts/run_demo.sh
```

This opens Mininet CLI after controller startup.

## Test Scenarios (Guideline-Aligned)
### Scenario 1: Allowed Traffic
In Mininet CLI:
```bash
h1 ping -c 3 h2
```
Expected result:
- Ping succeeds.
- Normal learning-switch forwarding behavior.

### Scenario 2: Suspicious Host Blocking
In Mininet CLI:
```bash
h4 ping -f -c 300 h2
```
Then:
```bash
h4 ping -c 3 h2
```
Expected result:
- Controller detects high packet rate from h4.
- Drop flow gets installed for h4.
- Subsequent traffic from h4 is blocked during block window.

## Verify Blocking and Logs
From another terminal:
```bash
cd dynamic_host_blocking
./scripts/verify_blocking.sh 00:00:00:00:00:04
```

Manual checks:
```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows s1
tail -n 50 logs/block_events.log
```

Expected evidence:
- `priority=200` drop rule matching `eth_src=00:00:00:00:00:04`
- Log lines with `host_blocked` and `block_verified`

## Performance Observation (for report/viva)
Collect and compare:
- Latency before and after block (`ping`)
- Throughput behavior (`iperf` optional)
- Flow table changes (`ovs-ofctl dump-flows s1`)
- Event timestamps and packet counters in logs

## Notes
- This project is OpenFlow 1.3 based.
- Use sudo for Mininet/OVS commands.
- Clean stale Mininet state with `sudo mn -c` if needed.

## Troubleshooting
### Symptom: all pings fail (100% loss)
If `h1 ping h2` fails and `h4` flood test also fails immediately, the controller may
have crashed before Mininet traffic started.

Check controller log:
```bash
tail -n 80 logs/controller_stdout.log
```

If you see a traceback from `eventlet` / `dns` (greendns path), rebuild the venv:
```bash
./scripts/setup_env_arch.sh
```

The setup script now recreates a clean venv and installs a compatible `dnspython`
pin. The controller launcher also forces `EVENTLET_NO_GREENDNS=yes` before loading
Ryu.

## References
- Ryu SDN Framework documentation
- Mininet documentation
- OpenFlow 1.3 match-action model
