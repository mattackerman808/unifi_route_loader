# UniFi Static Route Manager

A production-ready Python tool for creating and managing static routes on UniFi controllers via the API.

**Compatible with:**
- UniFi OS (UDM, UDM-Pro, UDR, Cloud Key Gen2+)
- Legacy UniFi Controllers

The script automatically detects your controller type and uses the correct API endpoints.

## Features

- Create static routes from a text file (CIDR notation)
- Remove unused static routes with dry-run safety mode
- List existing static routes
- Support for both nexthop and interface-based routing
- Authenticate via username/password or API key
- Configuration file support with encrypted passwords
- Automatic unique route naming with hash-based prefixes
- Batch route creation with duplicate detection
- Self-signed certificate support

## Installation

```bash
pip install -r requirements.txt
```

## Quick Start

Create a networks file (`networks.txt`) with one CIDR network per line:
```
10.10.0.0/24
172.16.0.0/16
192.168.100.0/24
```

Run the script (will prompt securely for password):
```bash
python create_static_routes.py -f networks.txt -n 192.168.1.254 -r "VPN Route"
```

## Configuration

### Using a Configuration File (Recommended)

Store settings in a YAML configuration file for easier management and automation.

**Option 1: API Key Authentication (Most Secure)**

Generate an API key in your UniFi controller:
- Go to **Settings** → **Admins & Users** → **API**
- Create a new API key and copy it

Create `config.yaml`:
```yaml
file: networks.txt
route_name: VPN Route
nexthop: 192.168.1.254
host: 192.168.1.1
port: 443
site: default
api_key: your_api_key_here
distance: 1
```

**Option 2: Encrypted Password Authentication**

For username/password authentication with encryption:

```bash
# Generate encrypted password
python encrypt_password.py
```

Create `config.yaml` with the encrypted password:
```yaml
file: networks.txt
route_name: VPN Route
nexthop: 192.168.1.254
host: 192.168.1.1
username: admin
password_encrypted: gAAAAABm...your_encrypted_password...
port: 443
site: default
distance: 1
```

Run with config file:
```bash
python create_static_routes.py --config config.yaml
```

### Command Line Arguments

**Required:**
- `-f, --file`: Text file with networks in CIDR notation (one per line)
- `-r, --route-name`: Base name for routes (unique prefixes added automatically)

**Gateway (choose one):**
- `-n, --nexthop`: Next hop IP address (gateway)
- `-w, --wan-interface`: WAN interface name (e.g., "wan", "wan2")

**Optional:**
- `--config`: Path to YAML configuration file
- `--api-key`: API key for authentication
- `--password`: Admin password (prompted if not provided)
- `--host`: Controller hostname/IP (default: 192.168.1.1)
- `--username`: Admin username (default: admin)
- `--site`: Site name (default: default)
- `-d, --distance`: Administrative distance (default: 1)
- `--port`: Controller port (default: 443)
- `--list-only`: List existing routes without creating new ones
- `--remove-unused`: Dry-run mode - show routes that would be removed
- `--remove-unused-confirm`: Actually remove unused routes (DANGEROUS)
- `--route-name-filter`: Only consider routes matching this text for removal
- `--debug`: Show detailed debug information

## Examples

### Create Routes via Nexthop

```bash
python create_static_routes.py -f networks.txt -n 192.168.1.254 -r "VPN Route"
```

Creates routes with unique prefixes:
- "VPN Route a34d80" → 10.10.0.0/24 via 192.168.1.254
- "VPN Route 15c144" → 172.16.0.0/16 via 192.168.1.254

### Create Routes via WAN Interface

```bash
python create_static_routes.py -f networks.txt -w wan2 -r "WAN2 Route"
```

Common interface names: `wan`, `wan2`, `wan3`

### List Existing Routes

```bash
python create_static_routes.py --list-only --host 192.168.1.1
```

### Remove Unused Routes

```bash
# Preview what would be removed (dry-run)
python create_static_routes.py -f networks.txt -n 192.168.1.254 --remove-unused

# Actually remove (use with caution)
python create_static_routes.py -f networks.txt -n 192.168.1.254 \
  --remove-unused-confirm --route-name-filter "VPN Route"
```

### Custom Controller and Distance

```bash
python create_static_routes.py -f networks.txt -n 192.168.1.254 -r "Backup" \
  --host 192.168.1.10 -d 10
```

## Route Management

### Route Naming

Each route is automatically assigned a unique 6-character prefix based on its network address hash:
- Same network always gets the same prefix
- Prevents naming conflicts
- Consistent regardless of creation order

Example: "VPN Route a34d80", "VPN Route 15c144"

### Route Removal

**Safety Features:**
- Dry-run mode by default (preview changes)
- Route name filtering (only remove matching routes)
- Explicit confirmation required

**Workflow:**
1. Fetch existing routes
2. Create new routes from file
3. Identify unused routes
4. Remove (only if confirmed)

**Dry-Run Example:**
```bash
python create_static_routes.py -f networks.txt -n 192.168.1.254 \
  --remove-unused --route-name-filter "VPN Route"
```

**Actual Removal:**
```bash
python create_static_routes.py -f networks.txt -n 192.168.1.254 \
  --remove-unused-confirm --route-name-filter "VPN Route"
```

## Authentication Methods

Listed from most to least secure:

### 1. API Key (Most Secure)

Generate in controller: **Settings** → **Admins & Users** → **API**

```yaml
api_key: your_api_key_here
```

Benefits: No password storage, easy rotation, safe for automation

### 2. Encrypted Password

```bash
python encrypt_password.py
```

Add to config:
```yaml
password_encrypted: gAAAAABm...encrypted_string...
```

Security: Encryption key stored in `~/.unifi_route_loader.key` (mode 0600)

### 3. Interactive Password Prompt

Omit password from config/command line - script will prompt securely

```bash
python create_static_routes.py -f networks.txt -n 192.168.1.254 -r "VPN"
# Will prompt: Password for admin@192.168.1.1:
```

### 4. Plain Text (Not Recommended)

For testing only:
```yaml
password: mypassword
```

## Networks File Format

One network per line in CIDR notation:
```
# Comments start with #
10.10.0.0/24
172.16.0.0/16
192.168.100.0/24

# Empty lines are ignored
10.20.0.0/22
```

## Troubleshooting

### 401 Unauthorized

Most common cause: Using Ubiquiti cloud/SSO account instead of local account.

**Solution:**
1. Go to Settings → System → Advanced (UniFi OS) or Settings → Admins (Legacy)
2. Create a local admin account
3. Use that account with the script

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for detailed steps.

### Connection Issues
- Verify controller hostname/IP
- Ensure port 443 is accessible
- Check firewall rules

### Authentication Fails
- Verify username and password
- Ensure account has admin privileges
- Confirm site name is correct
- Check that 2FA is not enabled (API doesn't support 2FA)

### Route Creation Fails
- Verify networks use valid CIDR notation
- Ensure nexthop IP is reachable from gateway
- Check for conflicting routes
- Verify file exists and is readable

## Production Best Practices

1. **Use API keys** for automation and production
2. **Use encrypted passwords** if API keys aren't available
3. **Never commit** plain text passwords or encryption keys to version control
4. **Always test with dry-run** before removing routes
5. **Use route name filters** to prevent accidental deletion
6. **Backup your configuration** before making changes
7. **Start with small batches** before bulk operations
8. **Monitor route creation** in the UniFi controller UI
9. **Test in a lab** environment first if possible
10. **Keep the script updated** to the latest version

## How It Works

The script automatically:
1. Detects controller type (UniFi OS vs Legacy)
2. Extracts CSRF tokens for UniFi OS
3. Resolves interface names to internal IDs
4. Handles authentication securely
5. Batch creates routes with duplicate detection
6. Generates consistent unique route identifiers

## Help

```bash
python create_static_routes.py --help
```

## License

MIT License - Copyright (c) 2026 UniFi Static Route Manager Contributors

## Notes

- SSL verification disabled by default for self-signed certificates
- Script automatically logs in and out
- All routes from file use the same gateway/interface
- Empty lines and comments (#) in networks file are ignored
- Password prompts are secure (no terminal echo)
