# UniFi Static Route Manager

Python script to create and manage static routes on UniFi controllers via the API using command line arguments.

**Compatible with:**
- Legacy UniFi Controllers
- UniFi OS (UDM, UDM-Pro, UDR, Cloud Key Gen2+)

The script automatically detects your controller type and uses the correct API endpoints.

## Features

- Authenticate with UniFi Controller (username/password or API key)
- Create static routes from a text file with CIDR notation
- List existing static routes
- Support for self-signed certificates
- Batch route creation with automatic numbering
- Command-line interface
- Configuration file support with encrypted passwords or API keys

## Installation

Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Using a Configuration File (Recommended)

You can store all your settings in a YAML configuration file for easier management and automation.

#### Authentication Options

The script supports two authentication methods:

**Option 1: API Key Authentication (Recommended)**

API keys provide better security and access control without storing passwords.

1. Generate an API key in your UniFi controller:
   - Go to **Settings** → **Admins & Users** → **API**
   - Create a new API key
   - Copy the generated key (e.g., `LoTQgF3A2Hspj_7BPkGmyqJ1DNrkH6-n`)

2. Create your `config.yaml` file:
```yaml
# Required settings
file: networks.txt
route_name: VPN Route

# Gateway (choose one)
nexthop: 192.168.1.254
# wan_interface: wan2

# Connection settings
host: 192.168.77.1
port: 443
site: default

# API Key Authentication
api_key: LoTQgF3A2Hspj_7BPkGmyqJ1DNrkH6-n

# Optional settings
distance: 1
```

3. Run with the config file:
```bash
python create_static_routes.py --config config.yaml
```

**Option 2: Username/Password Authentication**

For username/password authentication, you can use encrypted passwords for better security:

1. Generate an encrypted password:

Run the password encryption utility:

```bash
python encrypt_password.py
```

The utility will:
1. Prompt you to enter your password (securely, without echoing)
2. Create an encryption key in `~/.unifi_route_loader.key`
3. Display the encrypted password string

Example output:
```
UniFi Route Loader - Password Encryption Utility
==================================================

This utility will encrypt your password for use in the config file.
The encryption key will be stored securely in your home directory.

Enter password to encrypt: [hidden]
Confirm password: [hidden]

✓ Password encrypted successfully!

Add this line to your config.yaml file:
--------------------------------------------------
password_encrypted: gAAAAABm...your_encrypted_password_here...
--------------------------------------------------
```

2. Create your config file:

Create a `config.yaml` file (see `config.yaml.example` for reference):

```yaml
# Required settings
file: networks.txt
route_name: VPN Route

# Gateway (choose one)
nexthop: 192.168.1.254
# wan_interface: wan2

# Connection settings
host: 192.168.1.1
username: admin
port: 443
site: default

# Encrypted password (from step 1)
password_encrypted: gAAAAABm...your_encrypted_password_here...

# Optional settings
distance: 1
list_only: false
debug: false
```

3. Run with the config file:

```bash
python create_static_routes.py --config config.yaml
```

You can override any config file setting with command line options:

```bash
# Use config file but override the route name
python create_static_routes.py --config config.yaml -r "Different Route Name"

# Use config file but enable debug mode
python create_static_routes.py --config config.yaml --debug
```

### Basic Syntax

```bash
# Using nexthop IP address (will prompt for password)
python create_static_routes.py -f <networks_file> -n <nexthop> -r <route_name>

# Using WAN interface (with password on command line - not recommended)
python create_static_routes.py -f <networks_file> -w <wan_interface> -r <route_name> --password <password>
```

**Security Note:** If you don't provide `--password` on the command line, the script will prompt you securely. This is the recommended approach to avoid exposing passwords in shell history.

### Required Arguments

- `-f, --file`: Text file containing networks in CIDR notation (one per line)
- `-r, --route-name`: Base name for routes (numbers will be appended automatically)

### Gateway Options (choose one)

- `-n, --nexthop`: Next hop IP address (gateway) for all routes
- `-w, --wan-interface`: WAN interface name for all routes (e.g., "wan", "wan2")

**Note:** You must specify either `--nexthop` OR `--wan-interface`, but not both.

### Optional Arguments

- `--config`: Path to YAML configuration file
- `--api-key`: API key for authentication (alternative to username/password)
- `--password`: Admin password (will prompt securely if not provided)
- `--host`: UniFi controller hostname or IP (default: 192.168.1.1)
- `--username`: Admin username (default: admin)
- `--site`: Site name (default: default)
- `-d, --distance`: Administrative distance (default: 1)
- `--port`: Controller port (default: 443)
- `--list-only`: Only list existing routes without creating new ones
- `--debug`: Show detailed debug information including API requests and responses

## How It Works

The script automatically:
1. **Detects controller type** - Tries both UniFi OS and Legacy API endpoints
2. **Extracts CSRF tokens** - For UniFi OS, extracts and uses CSRF tokens from JWT cookies
3. **Resolves interface IDs** - Converts interface names (wan2) to internal IDs
4. **Handles authentication** - Securely prompts for passwords if not provided
5. **Batch creates routes** - Processes all networks from your file with automatic naming

## Examples

### Create Routes Using Nexthop IP

1. Create a text file `networks.txt` with your networks:
```
10.10.0.0/24
172.16.0.0/16
10.20.0.0/24
```

2. Run the script (will prompt for password):
```bash
python create_static_routes.py \
  -f networks.txt \
  -n 192.168.1.254 \
  -r "VPN Route"
```

You'll be prompted:
```
Password for admin@192.168.1.1: [password hidden]
```

This will create routes named:
- "VPN Route 1" → 10.10.0.0/24 via 192.168.1.254
- "VPN Route 2" → 172.16.0.0/16 via 192.168.1.254
- "VPN Route 3" → 10.20.0.0/24 via 192.168.1.254

### Create Routes Using WAN Interface

Route traffic through a specific WAN interface (e.g., WAN2 for failover or load balancing):

```bash
python create_static_routes.py \
  -f networks.txt \
  -w wan2 \
  -r "WAN2 Route" \
  --host unifi.example.com \
  --username admin
```

This will create interface-based routes:
- "WAN2 Route 1" → 10.10.0.0/24 via interface wan2
- "WAN2 Route 2" → 172.16.0.0/16 via interface wan2
- "WAN2 Route 3" → 10.20.0.0/24 via interface wan2

Common interface names:
- `wan` - Primary WAN interface
- `wan2` - Secondary WAN interface
- `wan3` - Tertiary WAN interface (if available)

### With Custom Controller

```bash
python create_static_routes.py \
  -f networks.txt \
  -n 10.0.0.1 \
  -r "Office Routes" \
  --host 192.168.1.10 \
  --username admin
```

### With Custom Distance

```bash
python create_static_routes.py \
  -f networks.txt \
  -n 192.168.1.254 \
  -r "Backup Route" \
  -d 10
```

### List Existing Routes Only

```bash
python create_static_routes.py \
  -f networks.txt \
  -n 192.168.1.1 \
  -r "Dummy" \
  --list-only
```

### Using Password on Command Line (Not Recommended)

If you need to use the script in automation where prompting isn't possible:

```bash
python create_static_routes.py \
  -f networks.txt \
  -n 192.168.1.254 \
  -r "VPN Route" \
  --password "your_password"
```

**Warning:** Passwords on command line may be visible in process lists and shell history.

### Using API Key Authentication

Using an API key is the most secure method and recommended for automation:

```bash
python create_static_routes.py \
  -f networks.txt \
  -n 192.168.1.254 \
  -r "VPN Route" \
  --host 192.168.77.1 \
  --api-key LoTQgF3A2Hspj_7BPkGmyqJ1DNrkH6-n
```

Or better yet, use a config file with the API key:

```yaml
file: networks.txt
route_name: VPN Route
nexthop: 192.168.1.254
host: 192.168.77.1
api_key: LoTQgF3A2Hspj_7BPkGmyqJ1DNrkH6-n
```

Then run:
```bash
python create_static_routes.py --config config.yaml
```

## Networks File Format

Create a text file with one network per line in CIDR notation:

```
# This is a comment - lines starting with # are ignored
10.10.0.0/24
172.16.0.0/16
192.168.100.0/24

# Empty lines are also ignored
10.20.0.0/22
```

## Authentication Security

The script offers multiple authentication methods, listed from most to least secure:

### 1. API Key Authentication (Most Secure)

Use API keys generated through the UniFi controller interface:

```bash
python create_static_routes.py --config config.yaml --api-key LoTQgF3A2Hspj_7BPkGmyqJ1DNrkH6-n
```

Or in your config file:
```yaml
api_key: LoTQgF3A2Hspj_7BPkGmyqJ1DNrkH6-n
```

**Benefits:**
- No password storage required
- Fine-grained access control through the UniFi controller
- Easy to rotate or revoke without changing passwords
- Works with UniFi OS (UDM, UDM-Pro, etc.)
- Safe to use in automation scripts

**To generate an API key:**
1. Log into your UniFi controller web interface
2. Navigate to **Settings** → **Admins & Users** → **API**
3. Click **Create New API Key**
4. Copy the generated key and use it in your config file or command line

### 2. Encrypted Password in Config File (Secure for Automation)

Use the `encrypt_password.py` utility to generate an encrypted password:

```bash
python encrypt_password.py
```

Add the encrypted password to your config file:

```yaml
password_encrypted: gAAAAABm...encrypted_string_here...
```

**Security Notes:**
- The encryption key is stored in `~/.unifi_route_loader.key` with 0600 permissions
- Only works on the same system with the same encryption key
- Safe to commit the config file (with encrypted password) to version control
- Do NOT commit the `.key` file to version control

### 3. Interactive Password Prompt (Secure for Manual Use)

Simply omit the password from both command line and config file:

```bash
python create_static_routes.py --config config.yaml
# Will prompt: Password for admin@192.168.1.1:
```

This method prevents passwords from appearing in:
- Shell command history
- Process listings
- Log files
- Screen captures

### 4. Plain Text Password (Least Secure - Not Recommended)

For testing only:

```bash
# Command line (visible in history and process list)
python create_static_routes.py -f networks.txt -n 192.168.1.254 -r "VPN" --password mypassword

# Config file (visible to anyone with file access)
password: mypassword
```

**Warning:** Only use this for testing. Passwords will be visible in command history, process listings, and files.

## Command Line Help

View all available options:
```bash
python create_static_routes.py --help
```

## Notes

- The script disables SSL certificate verification by default for self-signed certificates
- Routes are automatically named with sequential numbers (e.g., "VPN Route 1", "VPN Route 2")
- All routes from the file will use the same nexthop gateway or interface
- The script logs in and out automatically
- Empty lines and comments (starting with #) in the networks file are ignored
- **Password Security:** By default, the script prompts for passwords securely without echoing to the terminal. This prevents passwords from appearing in:
  - Shell command history
  - Process listings (ps, top, etc.)
  - Log files
  - Screen captures

## Troubleshooting

### 401 Unauthorized Errors

The most common cause is using a Ubiquiti cloud/SSO account instead of a local account. **The API requires a local account.**

**Quick Fix:**
1. Go to Settings → System → Advanced (UniFi OS) or Settings → Admins (Legacy)
2. Create a local admin account
3. Use that account with the script

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for detailed steps.

### Connection Issues
- Verify controller hostname/IP is correct
- Ensure port 443 is accessible
- Check firewall rules

### Authentication Fails
- Verify username and password are correct
- Ensure the user has admin privileges
- Check that the site name matches your UniFi site

### Route Creation Fails
- Verify networks in file are in valid CIDR notation
- Ensure the nexthop IP is reachable from the UniFi gateway
- Check that routes don't conflict with existing routes
- Verify the networks file exists and is readable
