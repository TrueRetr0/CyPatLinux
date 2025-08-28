#!/bin/bash

#########################################################
# CyberPatriot Linux Security Hardening Script
# Version: 1.0
# Description: Comprehensive security hardening for Ubuntu/Debian
#########################################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log file
LOG_FILE="/var/log/cyberpatriot_hardening.log"
BACKUP_DIR="/root/cyberpatriot_backups"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[*]${NC} $1"
    echo "[$(date)] $1" >> "$LOG_FILE"
}

print_good() {
    echo -e "${GREEN}[+]${NC} $1"
    echo "[$(date)] SUCCESS: $1" >> "$LOG_FILE"
}

print_error() {
    echo -e "${RED}[-]${NC} $1"
    echo "[$(date)] ERROR: $1" >> "$LOG_FILE"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    echo "[$(date)] WARNING: $1" >> "$LOG_FILE"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root"
   exit 1
fi

print_status "Starting CyberPatriot Security Hardening Script..."
print_status "Logging to: $LOG_FILE"

#########################################################
# SECTION 1: USER AND GROUP MANAGEMENT
#########################################################

print_status "=== SECTION 1: USER AND GROUP MANAGEMENT ==="

# Backup passwd, shadow, and group files
cp /etc/passwd "$BACKUP_DIR/passwd.bak"
cp /etc/shadow "$BACKUP_DIR/shadow.bak"
cp /etc/group "$BACKUP_DIR/group.bak"

# Check for users with UID 0 besides root
print_status "Checking for users with UID 0..."
awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd | while read user; do
    print_warning "User $user has UID 0! Consider removing or changing UID"
done

# Check for empty passwords
print_status "Checking for empty passwords..."
awk -F: '($2 == "" || $2 == "!" || $2 == "*") {print $1}' /etc/shadow | while read user; do
    if [ "$user" != "root" ]; then
        print_warning "User $user has empty/disabled password"
    fi
done

# Disable guest account
print_status "Disabling guest account..."
echo "allow-guest=false" >> /etc/lightdm/lightdm.conf 2>/dev/null

# Lock unnecessary system accounts
print_status "Locking system accounts..."
for user in bin daemon adm lp sync shutdown halt mail news uucp operator games nobody; do
    usermod -L $user 2>/dev/null
    usermod -s /usr/sbin/nologin $user 2>/dev/null
done

# Set password expiration policies
print_status "Setting password aging policies..."
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

# Remove unauthorized users (requires authusers.txt file)
if [ -f "authusers.txt" ]; then
    print_status "Checking for unauthorized users..."
    getent passwd | cut -d: -f1 | while read user; do
        if ! grep -q "^$user$" authusers.txt && [ "$user" != "root" ] && [ "$user" != "nobody" ]; then
            if id -u "$user" >/dev/null 2>&1 && [ $(id -u "$user") -ge 1000 ]; then
                print_warning "Unauthorized user found: $user (consider removing)"
                # Uncomment to auto-remove: userdel -r $user
            fi
        fi
    done
else
    print_warning "authusers.txt not found - skipping unauthorized user check"
fi

# Remove users from sudo group if not authorized
print_status "Checking sudo group membership..."
getent group sudo | cut -d: -f4 | tr ',' '\n' | while read user; do
    if [ -f "authsudo.txt" ]; then
        if ! grep -q "^$user$" authsudo.txt; then
            print_warning "User $user in sudo group but not in authsudo.txt"
            # Uncomment to remove: gpasswd -d $user sudo
        fi
    fi
done

#########################################################
# SECTION 2: PAM CONFIGURATION
#########################################################

print_status "=== SECTION 2: PAM CONFIGURATION ==="

# Backup PAM files
cp -r /etc/pam.d "$BACKUP_DIR/"

# Install PAM modules
print_status "Installing PAM modules..."
apt-get update -qq
apt-get install -y -qq libpam-pwquality libpam-cracklib 2>/dev/null

# Configure password quality requirements
print_status "Configuring password quality..."
cat > /etc/security/pwquality.conf << EOF
# Password Quality Configuration
minlen = 12
dcredit = -1
ucredit = -1
ocredit = -1
lcredit = -1
retry = 3
maxrepeat = 3
gecoscheck = 1
enforce_for_root
EOF

# Configure PAM password requirements
print_status "Updating PAM password settings..."
if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
    sed -i '/pam_unix.so/ i password requisite pam_pwquality.so retry=3' /etc/pam.d/common-password
fi

# Set up account lockout policy
print_status "Configuring account lockout..."
cat >> /etc/pam.d/common-auth << EOF
# Account Lockout Policy
auth required pam_tally2.so onerr=fail audit silent deny=5 unlock_time=900
EOF

# Enable password history
if ! grep -q "remember=" /etc/pam.d/common-password; then
    sed -i 's/pam_unix.so/pam_unix.so remember=5/' /etc/pam.d/common-password
fi

# Configure su access
print_status "Restricting su access..."
echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su
groupadd -f wheel

#########################################################
# SECTION 3: SSH HARDENING
#########################################################

print_status "=== SECTION 3: SSH HARDENING ==="

# Backup SSH config
cp /etc/ssh/sshd_config "$BACKUP_DIR/"

# SSH Hardening
print_status "Hardening SSH configuration..."
cat > /etc/ssh/sshd_config.d/99-hardening.conf << EOF
# SSH Hardening Configuration
Protocol 2
Port 22
PermitRootLogin no
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 0
LoginGraceTime 60
Banner /etc/ssh/banner
PubkeyAuthentication yes
IgnoreRhosts yes
HostbasedAuthentication no
StrictModes yes
AllowUsers *@*
DenyUsers root
LogLevel VERBOSE
EOF

# Create SSH banner
cat > /etc/ssh/banner << EOF
###############################################################
#                      AUTHORIZED ACCESS ONLY                #
#  Unauthorized access to this system is strictly prohibited #
#      All access attempts are logged and monitored         #
###############################################################
EOF

# Generate strong SSH host keys if needed
print_status "Checking SSH host keys..."
ssh-keygen -A

# Restart SSH service
systemctl restart sshd

#########################################################
# SECTION 4: FIREWALL CONFIGURATION
#########################################################

print_status "=== SECTION 4: FIREWALL CONFIGURATION ==="

# Install and configure UFW
print_status "Installing and configuring UFW..."
apt-get install -y -qq ufw 2>/dev/null

# Reset UFW to defaults
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed

# Allow SSH (adjust as needed)
ufw allow 22/tcp comment 'SSH'

# Allow other services as needed (uncomment as required)
# ufw allow 80/tcp comment 'HTTP'
# ufw allow 443/tcp comment 'HTTPS'
# ufw allow 53 comment 'DNS'

# Enable UFW
ufw --force enable

# Configure iptables for additional protection
print_status "Configuring iptables rules..."

# Save current rules
iptables-save > "$BACKUP_DIR/iptables.rules"

# Protect against common attacks
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -f -j DROP
iptables -A INPUT -p tcp --dport 23 -j DROP  # Telnet

#########################################################
# SECTION 5: SERVICE MANAGEMENT
#########################################################

print_status "=== SECTION 5: SERVICE MANAGEMENT ==="

# List of services commonly disabled in CyberPatriot
BAD_SERVICES=(
    "telnet"
    "rsh-client"
    "rsh-server"
    "nis"
    "tftp"
    "talk"
    "ntalk"
    "rlogin"
    "vsftpd"
    "pure-ftpd"
    "proftpd"
    "apache2"
    "nginx"
    "snmpd"
    "samba"
    "nfs-kernel-server"
    "bind9"
    "dnsmasq"
    "dovecot"
    "postfix"
    "xinetd"
    "inetutils-inetd"
    "openbsd-inetd"
)

# Stop and disable unnecessary services
for service in "${BAD_SERVICES[@]}"; do
    if systemctl list-unit-files | grep -q "$service"; then
        print_status "Disabling service: $service"
        systemctl stop "$service" 2>/dev/null
        systemctl disable "$service" 2>/dev/null
    fi
done

# Check for running services on suspicious ports
print_status "Checking for services on suspicious ports..."
netstat -tulpn | grep LISTEN

#########################################################
# SECTION 6: PACKAGE MANAGEMENT
#########################################################

print_status "=== SECTION 6: PACKAGE MANAGEMENT ==="

# Update package lists
print_status "Updating package lists..."
apt-get update -qq

# Remove potentially unwanted packages
UNWANTED_PACKAGES=(
    "john"
    "john-data"
    "hydra"
    "hydra-gtk"
    "aircrack-ng"
    "fcrackzip"
    "lcrack"
    "ophcrack"
    "ophcrack-cli"
    "pdfcrack"
    "pyrit"
    "rarcrack"
    "sipcrack"
    "irpas"
    "logkeys"
    "zeitgeist-core"
    "zeitgeist-datahub"
    "python-zeitgeist"
    "rhythmbox-plugin-zeitgeist"
    "zeitgeist"
    "nmap"
    "zenmap"
    "wireshark"
    "tcpdump"
    "netcat"
    "netcat-traditional"
    "netcat-openbsd"
    "nikto"
    "kismet"
)

for package in "${UNWANTED_PACKAGES[@]}"; do
    if dpkg -l | grep -q "^ii.*$package"; then
        print_warning "Found potentially unwanted package: $package"
        # Uncomment to auto-remove: apt-get remove -y --purge $package
    fi
done

# Install security tools
print_status "Installing security tools..."
apt-get install -y -qq \
    aide \
    rkhunter \
    chkrootkit \
    clamav \
    clamav-daemon \
    fail2ban \
    auditd \
    apparmor \
    apparmor-utils

# Update virus definitions
print_status "Updating ClamAV..."
freshclam

#########################################################
# SECTION 7: FILE PERMISSIONS AND OWNERSHIP
#########################################################

print_status "=== SECTION 7: FILE PERMISSIONS AND OWNERSHIP ==="

# Set proper permissions on important files
print_status "Setting file permissions..."
chmod 644 /etc/passwd
chmod 000 /etc/shadow
chmod 644 /etc/group
chmod 000 /etc/gshadow
chmod 600 /etc/ssh/sshd_config
chmod 644 /etc/issue
chmod 644 /etc/issue.net

# Set proper ownership
chown root:root /etc/passwd
chown root:shadow /etc/shadow
chown root:root /etc/group
chown root:shadow /etc/gshadow

# Find and secure SUID/SGID files
print_status "Finding SUID/SGID files..."
find / -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; 2>/dev/null > "$BACKUP_DIR/suid_sgid_files.txt"

# Find world-writable files
print_status "Finding world-writable files..."
find / -type f -perm -002 2>/dev/null > "$BACKUP_DIR/world_writable_files.txt"

# Find unowned files
print_status "Finding unowned files..."
find / -nouser -o -nogroup 2>/dev/null > "$BACKUP_DIR/unowned_files.txt"

# Check for .rhosts and .netrc files
print_status "Checking for .rhosts and .netrc files..."
find /home -name ".rhosts" -o -name ".netrc" 2>/dev/null | while read file; do
    print_warning "Found $file - consider removing"
    # Uncomment to remove: rm -f "$file"
done

#########################################################
# SECTION 8: KERNEL HARDENING
#########################################################

print_status "=== SECTION 8: KERNEL HARDENING ==="

# Backup sysctl config
cp /etc/sysctl.conf "$BACKUP_DIR/"

print_status "Applying kernel hardening..."
cat > /etc/sysctl.d/99-hardening.conf << EOF
# Kernel Hardening Configuration

# IP Forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Source packet verification
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Accept ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Accept secure ICMP redirects
net.ipv4.conf.all.secure_redirects = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# SYN cookies
net.ipv4.tcp_syncookies = 1

# Accept source route
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# IPv6 advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Core dumps
fs.suid_dumpable = 0

# ASLR
kernel.randomize_va_space = 2

# Kernel pointers
kernel.kptr_restrict = 2

# Ptrace scope
kernel.yama.ptrace_scope = 1

# Core dump restrictions
kernel.core_uses_pid = 1

# Sysrq
kernel.sysrq = 0

# Message restrictions
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296

# Panic timeout
kernel.panic = 10

# PID max
kernel.pid_max = 65536

# TCP timestamps
net.ipv4.tcp_timestamps = 0

# ARP
net.ipv4.conf.all.arp_ignore = 1
net.ipv4.conf.all.arp_announce = 2
EOF

# Apply sysctl settings
sysctl -p /etc/sysctl.d/99-hardening.conf

#########################################################
# SECTION 9: AUDIT AND LOGGING
#########################################################

print_status "=== SECTION 9: AUDIT AND LOGGING ==="

# Configure auditd
print_status "Configuring audit rules..."
cat > /etc/audit/rules.d/hardening.rules << EOF
# Audit Rules for CyberPatriot

# Remove any existing rules
-D

# Buffer size
-b 8192

# Failure handling
-f 1

# Monitor authentication
-w /var/log/faillog -p wa -k auth_failures
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session

# Monitor user/group changes
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/gshadow -p wa -k gshadow_changes
-w /etc/security/opasswd -p wa -k opasswd_changes

# Monitor sudoers
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d -p wa -k sudoers_changes

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config

# Monitor system calls
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b64 -S socket -S connect -k network
-a always,exit -F arch=b64 -S open -S openat -F exit=-EPERM -k access
EOF

# Restart auditd
systemctl restart auditd

# Configure rsyslog
print_status "Configuring rsyslog..."
systemctl enable rsyslog
systemctl start rsyslog

# Set log permissions
chmod -R 640 /var/log/

#########################################################
# SECTION 10: NETWORK CONFIGURATION
#########################################################

print_status "=== SECTION 10: NETWORK CONFIGURATION ==="

# Disable IPv6 if not needed
print_status "Checking IPv6 configuration..."
if ! grep -q "ipv6.disable=1" /etc/default/grub; then
    print_warning "IPv6 is enabled. Consider disabling if not needed."
fi

# Check hosts.allow and hosts.deny
print_status "Configuring TCP Wrappers..."
echo "ALL: LOCAL" > /etc/hosts.allow
echo "sshd: ALL" >> /etc/hosts.allow
echo "ALL: ALL" > /etc/hosts.deny

# Disable unnecessary network protocols
print_status "Disabling unnecessary protocols..."
cat > /etc/modprobe.d/blacklist-rare-network.conf << EOF
# Disable rare network protocols
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

#########################################################
# SECTION 11: CRON JOBS
#########################################################

print_status "=== SECTION 11: CRON JOBS ==="

# Set proper cron permissions
print_status "Setting cron permissions..."
chmod 600 /etc/crontab
chmod 700 /etc/cron.d
chmod 700 /etc/cron.daily
chmod 700 /etc/cron.hourly
chmod 700 /etc/cron.monthly
chmod 700 /etc/cron.weekly

# Check for unauthorized cron jobs
print_status "Checking cron jobs..."
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u $user -l 2>/dev/null | grep -v "^#" | grep -v "^$" > /dev/null
    if [ $? -eq 0 ]; then
        print_warning "User $user has cron jobs"
        crontab -u $user -l 2>/dev/null >> "$BACKUP_DIR/cron_jobs.txt"
    fi
done

#########################################################
# SECTION 12: SYSTEM INTEGRITY
#########################################################

print_status "=== SECTION 12: SYSTEM INTEGRITY ==="

# Initialize AIDE
print_status "Initializing AIDE..."
aideinit -y

# Run rootkit hunters
print_status "Running rootkit checks..."
rkhunter --update
rkhunter --propupd
chkrootkit -q > "$BACKUP_DIR/chkrootkit.log"

# Check for suspicious files
print_status "Checking for suspicious files..."
find / -name "*.mp3" -o -name "*.mov" -o -name "*.mp4" -o -name "*.avi" -o -name "*.mpg" -o -name "*.mpeg" -o -name "*.flac" -o -name "*.m4a" -o -name "*.flv" -o -name "*.ogg" -o -name "*.gif" -o -name "*.png" -o -name "*.jpg" -o -name "*.jpeg" 2>/dev/null > "$BACKUP_DIR/media_files.txt"

#########################################################
# SECTION 13: APPLICATION SPECIFIC
#########################################################

print_status "=== SECTION 13: APPLICATION SPECIFIC ==="

# MySQL Hardening (if installed)
if command -v mysql &> /dev/null; then
    print_status "MySQL detected - consider running mysql_secure_installation"
fi

# Apache Hardening (if installed)
if [ -d "/etc/apache2" ]; then
    print_status "Apache detected - applying hardening..."
    echo "ServerTokens Prod" >> /etc/apache2/conf-available/security.conf
    echo "ServerSignature Off" >> /etc/apache2/conf-available/security.conf
    a2enmod headers
    a2enmod rewrite
fi

# PHP Hardening (if installed)
if [ -f "/etc/php/7.4/apache2/php.ini" ]; then
    print_status "PHP detected - applying hardening..."
    sed -i 's/expose_php = On/expose_php = Off/' /etc/php/*/apache2/php.ini
    sed -i 's/allow_url_fopen = On/allow_url_fopen = Off/' /etc/php/*/apache2/php.ini
    sed -i 's/allow_url_include = On/allow_url_include = Off/' /etc/php/*/apache2/php.ini
fi

#########################################################
# SECTION 14: GRUB SECURITY
#########################################################

print_status "=== SECTION 14: GRUB SECURITY ==="

print_status "Checking GRUB configuration..."
if [ -f "/etc/default/grub" ]; then
    cp /etc/default/grub "$BACKUP_DIR/"
    print_warning "Consider setting a GRUB password with grub-mkpasswd-pbkdf2"
fi

#########################################################
# SECTION 15: COMPLIANCE CHECKS
#########################################################

print_status "=== SECTION 15: FINAL COMPLIANCE CHECKS ==="

# Check password policy
print_status "Password Policy Check:"
grep "^PASS" /etc/login.defs

# Check for null passwords
print_status "Null Password Check:"
awk -F: '($2 == "") {print $1}' /etc/shadow

# Check sudo configuration
print_status "Sudo Configuration Check:"
grep -v "^#" /etc/sudoers | grep -v "^$"

# Check listening ports
print_status "Listening Ports:"
ss -tulnp

# Check running processes
print_status "Checking for suspicious processes..."
ps aux | grep -E "(nc|netcat|/bin/sh|/bin/bash)" | grep -v grep

# Check system information
print_status "System Information:"
uname -a
lsb_release -a

#########################################################
# COMPLETION
#########################################################

print_good "=== SECURITY HARDENING COMPLETE ==="
print_status "Review the following files for findings:"
print_status "  - Log file: $LOG_FILE"
print_status "  - Backup directory: $BACKUP_DIR"
print_status "  - SUID/SGID files: $BACKUP_DIR/suid_sgid_files.txt"
print_status "  - World-writable files: $BACKUP_DIR/world_writable_files.txt"
print_status "  - Unowned files: $BACKUP_DIR/unowned_files.txt"
print_status "  - Media files: $BACKUP_DIR/media_files.txt"
print_status "  - Cron jobs: $BACKUP_DIR/cron_jobs.txt"

print_warning "IMPORTANT REMINDERS:"
print_warning "1. Create authorized user lists (authusers.txt, authsudo.txt)"
print_warning "2. Review and remove unauthorized users manually"
print_warning "3. Set strong passwords for all users"
print_warning "4. Review all warnings in the log file"
print_warning "5. Check for specific scenario requirements"
print_warning "6. Reboot may be required for some changes"

print_good "Script execution completed!"