# PiCrypt & PiDecrypt – Comprehensive README

## Overview
**PiCrypt & PiDecrypt** form a minimal pair of daemons that enable custom AES-256-GCM encryption of TCP/UDP payloads at the IP level. They are designed to work together automatically:

- **PiCrypt** runs on the **sender** side, intercepting and encrypting outbound packets.
- **PiDecrypt** runs on the **receiver** side, intercepting and decrypting inbound packets.

They use **Netfilter Queue** to hook into Linux’s packet processing, so that normal applications send and receive data as usual, but the payload is transparently encrypted in-flight.
- While intended for Raspberry Pi OS Linux devices, the programs may perform as intended with other operating systems. **Untested**
---

## How It Works

1. **Netfilter Queue**
   - On Linux, `iptables` can send packets to a queue instead of forwarding them immediately.
   - Both PiCrypt and PiDecrypt listen on queue #0.
   - They modify and reinject the packets into the network stack.

2. **AES-256-GCM Encryption**
   - Packets with **TCP** or **UDP** payloads are encrypted.
   - A 16-byte GCM tag is appended to the encrypted payload.
   - The checksums for IP and TCP/UDP are recomputed, ensuring packets remain valid.

3. **Minimal Configuration**
   - **Hard-coded key/IV** in each daemon must match.
   - Add one iptables rule on each system.
   - Run each daemon with root privileges.

---

## System Requirements
- Any Linux-based system with:
  - A working **iptables** and **Netfilter Queue** setup.
  - **libnetfilter_queue**, **OpenSSL** (for crypto), **gcc**.
- **Root permissions** to intercept packets.
- **TCP/UDP** traffic only (ICMP, ARP, or other protocols are passed unmodified).

---

## Installation & Setup

### 1. Install Dependencies (if not installed)
```bash
sudo apt-get update -y
sudo apt-get install -y libnetfilter-queue-dev libssl-dev openssl gcc
```

### 2. Obtain PiCrypt & PiDecrypt Source
You should have two C files:
- **PiCrypt.c**: The sender-side encryption daemon.
- **PiDecrypt.c**: The receiver-side decryption daemon.

### 3. Compile
```bash
# Sender side
gcc -o PiCrypt PiCrypt.c -lnetfilter_queue -lcrypto -lssl

# Receiver side
gcc -o PiDecrypt PiDecrypt.c -lnetfilter_queue -lcrypto -lssl
```

---

## Usage

### Sender Side (PiCrypt)
1. **Run PiCrypt**:
   ```bash
   sudo ./PiCrypt
   ```
   - This will run in the foreground. Press `CTRL+C` to stop.
2. **Add iptables Rule**:
   ```bash
   sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
   ```
   - This sends **all outbound** packets to queue #0.
   - PiCrypt intercepts and encrypts **TCP/UDP** payloads.

### Receiver Side (PiDecrypt)
1. **Run PiDecrypt**:
   ```bash
   sudo ./PiDecrypt
   ```
2. **Add iptables Rule**:
   ```bash
   sudo iptables -A INPUT -j NFQUEUE --queue-num 0
   ```
   - This sends **all inbound** packets to queue #0.
   - PiDecrypt intercepts and **decrypts** them if they have the AES-256-GCM tag.

### Checking it Works
- **Ping** from sender to receiver. If using TCP or UDP traffic, the payload portion will be encrypted, but you should still see connectivity.
- **tcpdump** on the wire to observe that the payload is unreadable.
- **Normal network usage** should still function if the key/IV match and the payload is recognized.

---

## Key/IV Management
- Both PiCrypt and PiDecrypt have the same **static key and IV** defined in their source.
- For improved security, consider generating keys dynamically or using a secure key exchange method.

---

## Protocol & Limitations
1. **TCP/UDP Payload Encryption**:
   - The IP + TCP/UDP headers are **not** encrypted.
   - Only the application data portion is.
   - A 16-byte tag is appended to each encrypted payload.
2. **No Fragment Handling**:
   - The sample code does not handle IP fragmentation.
   - Fragmented packets may cause problems.
3. **Non-TCP/UDP** Traffic**:
   - ICMP, ARP, and other protocols are **passed through** unmodified.
4. **Performance**:
   - AES-256-GCM encryption adds overhead.
   - For heavy traffic, consider hardware-accelerated crypto on supported hardware.

---

## Troubleshooting
1. **Packets Not Encrypted/Decrypted**:
   - Verify iptables rules are **added** and the counters are increasing.
   - Confirm PiCrypt/PiDecrypt are **running** (ps aux | grep PiCrypt / PiDecrypt).
2. **Decryption Fails**:
   - Ensure the **same key/IV** in both code files.
   - Make sure you’re sending TCP/UDP data, not a protocol that is left unencrypted.
3. **Network Issues**:
   - Remove the iptables rules:
     ```bash
     sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0
     sudo iptables -D INPUT -j NFQUEUE --queue-num 0
     ```
   - Check if connectivity is restored.
4. **Fragmentation**:
   - If you see large packets or mismatch between IP total length and actual packet size, you may need fragmentation handling.

---

## Additional Tips
- **Run in the Background**: You can daemonize PiCrypt / PiDecrypt using systemd or by removing the console output.
- **VPN Coexistence**: If you already run a VPN, the traffic might be encapsulated in another protocol. You can still intercept it if iptables sees the packets in clear form.
- **Security Hardening**: For production, consider ephemeral keys, logging, stricter firewall rules, and robust error handling.

---

## Conclusion
**PiCrypt & PiDecrypt** provide a **straightforward** example of transparent, packet-level AES-256-GCM encryption. By intercepting only TCP/UDP payloads and recalculating checksums, they preserve normal networking while adding an extra encryption layer. Just **compile**, **run**, and **add the iptables rules**—and your packets will be protected end-to-end.
