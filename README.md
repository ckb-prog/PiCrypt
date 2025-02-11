# PiCrypt
An open-source encryption mechanism for the Raspberry Pi
# PiCrypt – Network Encryption Daemon for Raspberry Pi 5
----------------------------------------------------------
## Overview
**PiCrypt** is a background service designed to intercept and (optionally) encrypt network traffic on your Raspberry Pi 5 using **Netfilter Queue** and **OpenSSL**. By default, it seamlessly passes traffic without modification—ensuring normal network usage—yet includes the hooks necessary to apply robust encryption (like **AES-256-GCM**). PiCrypt can also coexist with any existing VPN solution.

---

## Features
- **Automatic Daemon**: Runs in the background, detaching from the terminal.
- **Dependency Installation**: Installs required dependencies (`libnetfilter-queue-dev`, `libssl-dev`, etc.) automatically (if not already installed).
- **Netfilter Queue Integration**: Routes IPv4 traffic from `iptables` to PiCrypt.
- **AES-256 Key Generation**: Generates a 256-bit key and 128-bit IV using the OpenSSL RNG.
- **Seamless Network Usage**: By default, PiCrypt does not alter packets, so normal traffic flows uninterrupted.
- **Easy VPN Compatibility**: Works alongside typical VPNs (WireGuard, OpenVPN, etc.), or without them.
- **Systemd Support**: Optional systemd unit file for auto-start on boot.

---

## Disclaimer
1. **This project is a demonstration**: For real-world encryption, you’ll need a **matching decryption mechanism** on the receiving end.
2. **Altering packets** for encryption typically breaks normal communication unless the remote host expects the modified (encrypted) packet.
3. **Security**: Despite the advanced cryptographic functions available, you remain responsible for **properly securing** your environment, implementing safe key exchange, and abiding by relevant laws.
4. **Platform Compatibility**: This README assumes **Raspberry Pi OS** (Debian-based). Commands may differ slightly on other platforms.

---

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Installation & Compilation](#installation--compilation)
3. [Usage](#usage)
4. [Network Configuration (iptables)](#network-configuration-iptables)
5. [Verifying PiCrypt is Working](#verifying-picrypt-is-working)
6. [Enabling PiCrypt on Boot with Systemd](#enabling-picrypt-on-boot-with-systemd)
7. [Implementing Actual Encryption](#implementing-actual-encryption)
8. [Troubleshooting](#troubleshooting)
9. [License](#license)

---

## Prerequisites
- **Raspberry Pi 5** (or compatible system running Linux kernel with Netfilter Queue support).
- **root/sudo access**: Required for installing dependencies, setting iptables, and binding Netfilter.

---

## Installation & Compilation
### 1. Clone or Download Source Code
```bash
git clone https://github.com/your-username/picrypt.git
cd picrypt
```

### 2. Build PiCrypt
```bash
gcc -o picrypt picrypt.c -lnetfilter_queue -lcrypto -lssl
```

> **Note**: The code automatically attempts to install dependencies when run, but you can also manually install them:
> ```bash
> sudo apt-get update -y
> sudo apt-get install -y libnetfilter-queue-dev libssl-dev openssl
> ```

---

## Usage
### 1. Run PiCrypt as a Daemon
Simply run:
```bash
sudo ./picrypt
```
When launched, PiCrypt:
- **Forks twice** to run in the background (no terminal needed).
- Installs dependencies if missing.
- Initializes Netfilter Queue.
- Generates AES-256 keys (in case you want to enable real encryption).
- Waits for and processes packets.

### 2. Check the Process
```bash
ps aux | grep picrypt
```
You should see `./picrypt` running as `root`. If you need to stop PiCrypt:
```bash
sudo pkill picrypt
```

---

## Network Configuration (iptables)
PiCrypt depends on **Netfilter Queue**. You must create rules to send traffic to the queue:
```bash
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
sudo iptables -A INPUT -j NFQUEUE --queue-num 0
```
Now, any packet entering or leaving your system is captured and passed to PiCrypt on **queue #0**.

> **Note**: If you have existing firewall rules, ensure these lines do not conflict with or get overridden by them.

---

## Verifying PiCrypt is Working
1. **Check iptables counters**:
   ```bash
   sudo iptables -L -n -v
   ```
   You should see **increasing packet/byte counters** for the rules pointing to `NFQUEUE num 0`.

2. **Test Network Usage**:
   - **Ping** a website:
     ```bash
     ping -c 3 www.google.com
     ```
   - **Browse** the web or run any Internet-based application.
   - If everything works normally, PiCrypt is passing traffic as-is.

3. **Real-Time Watch**:
   ```bash
   watch -d -n 2 'sudo iptables -L -n -v'
   ```
   This updates packet counters every 2 seconds, showing traffic is going through PiCrypt.

---

## Enabling PiCrypt on Boot with Systemd
1. **Create a service file**: `/etc/systemd/system/picrypt.service`
   ```ini
   [Unit]
   Description=PiCrypt Network Encryption Daemon
   After=network.target

   [Service]
   ExecStart=/home/ckb/picrypt/picrypt
   Restart=always
   User=root
   Group=root
   WorkingDirectory=/home/ckb/picrypt
   StandardOutput=null
   StandardError=journal

   [Install]
   WantedBy=multi-user.target
   ```
2. **Reload systemd**:
   ```bash
   sudo systemctl daemon-reload
   ```
3. **Enable & Start**:
   ```bash
   sudo systemctl enable picrypt
   sudo systemctl start picrypt
   ```
4. **Check Status**:
   ```bash
   sudo systemctl status picrypt
   ```
> PiCrypt will now automatically run on every reboot.

---

## Implementing Actual Encryption
- **Currently**, PiCrypt only intercepts and **passes unmodified** packets. This ensures your network stays intact.
- To **encrypt data**, you’d modify the `packet_callback()` function:
  1. Parse/strip essential headers so you don’t break them.
  2. Encrypt the payload with **AES-256-GCM** (using the generated key/IV).
  3. Adjust headers/checksums as needed.
  4. Forward the newly encrypted packet.
- **On the receiving host**, you would need a **matching decryption** mechanism. Without that, your traffic would be unreadable, leading to dropped or malformed packets.

---

## Troubleshooting
1. **PiCrypt Not Running**:
   - Check logs: `sudo journalctl -u picrypt` (if using systemd).
   - Ensure you compiled with the correct flags.
2. **Network Connectivity Issues**:
   - Temporarily remove the iptables rules:
     ```bash
     sudo iptables -D OUTPUT -j NFQUEUE --queue-num 0
     sudo iptables -D INPUT -j NFQUEUE --queue-num 0
     ```
   - Confirm if normal connectivity is restored.
3. **Packet Counters Not Increasing**:
   - Double-check the queue number matches PiCrypt’s queue.
   - Confirm the iptables rules are actually applied and no other firewall rules override them.
4. **VPN Conflicts**:
   - Typically, PiCrypt and VPN can coexist. If issues arise, ensure the **order** of iptables rules is correct and your VPN traffic is routed as intended.
5. **Performance Concerns**:
   - Encrypting packets can be CPU-intensive. Consider optimizing code or using hardware encryption features if your Pi supports them.

---

## License
This project does not currently specify a license, but you can assume it falls under a permissive license (e.g., **MIT**) for demonstration purposes. Always review licensing if you incorporate external libraries.

---

Feel free to create an **Issue** or submit a **Pull Request** on GitHub if you encounter bugs or have suggestions.

---

## Contributing
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Commit and push changes.
4. Submit a Pull Request for review.

Thank you for using **PiCrypt**! If you have any issues, questions, or feedback, feel free to reach out. Happy encrypting!

