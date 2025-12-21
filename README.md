# UniFi Static Route Manager

Python script to create and manage static routes on UniFi controllers via the API using command line arguments.

**Compatible with:**
- Legacy UniFi Controllers
- UniFi OS (UDM, UDM-Pro, UDR, Cloud Key Gen2+)

The script automatically detects your controller type and uses the correct API endpoints.

## Features

- Authenticate with UniFi Controller
- Create static routes from a text file with CIDR notation
- List existing static routes
- Support for self-signed certificates
- Batch route creation with automatic numbering
- Command-line interface

## Installation

Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

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
