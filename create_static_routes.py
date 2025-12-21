#!/usr/bin/env python3
"""
UniFi Controller Static Route Manager
Creates static routes via the UniFi Controller API
"""

import requests
import json
import urllib3
import argparse
import sys
import getpass
import base64
import yaml
import os
from cryptography.fernet import Fernet
from typing import Optional, Dict, List

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class UniFiController:
    def __init__(self, host: str, username: str, password: str, port: int = 443, site: str = 'default', verify_ssl: bool = False, unifios: bool = False):
        """
        Initialize UniFi Controller connection

        Args:
            host: Controller hostname or IP address
            username: Admin username
            password: Admin password
            port: Controller port (default: 443)
            site: Site name (default: 'default')
            verify_ssl: Verify SSL certificate (default: False)
            unifios: Use UniFi OS endpoints (auto-detected if not specified)
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.site = site
        self.verify_ssl = verify_ssl
        self.base_url = f"https://{host}:{port}"
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.logged_in = False
        self.is_unifios = unifios
        self.csrf_token = None

    def _extract_csrf_token(self) -> Optional[str]:
        """
        Extract CSRF token from JWT TOKEN cookie (UniFi OS only)

        Returns:
            CSRF token string, or None if not found
        """
        try:
            # Get the TOKEN cookie
            token_cookie = self.session.cookies.get('TOKEN')
            if not token_cookie:
                return None

            # JWT has 3 parts separated by dots: header.payload.signature
            parts = token_cookie.split('.')
            if len(parts) != 3:
                return None

            # Decode the payload (second part)
            # Add padding if needed for base64 decoding
            payload = parts[1]
            padding = 4 - (len(payload) % 4)
            if padding != 4:
                payload += '=' * padding

            decoded = base64.urlsafe_b64decode(payload)
            jwt_data = json.loads(decoded)

            # Extract csrfToken from the JWT payload
            csrf_token = jwt_data.get('csrfToken')
            return csrf_token
        except Exception as e:
            return None

    def login(self) -> bool:
        """
        Authenticate with the UniFi Controller
        Automatically tries both legacy and UniFi OS endpoints

        Returns:
            bool: True if login successful, False otherwise
        """
        # Try UniFi OS endpoint first (UDM, UDM-Pro, Cloud Key Gen2+)
        login_endpoints = [
            ("/api/auth/login", True),   # UniFi OS
            ("/api/login", False)         # Legacy controller
        ]

        payload = {
            "username": self.username,
            "password": self.password
        }

        last_error = None
        for endpoint, is_unifios in login_endpoints:
            login_url = f"{self.base_url}{endpoint}"
            try:
                response = self.session.post(login_url, json=payload)
                if response.status_code == 200:
                    self.logged_in = True
                    self.is_unifios = is_unifios
                    controller_type = "UniFi OS" if is_unifios else "Legacy UniFi Controller"

                    # Extract CSRF token for UniFi OS
                    if is_unifios:
                        self.csrf_token = self._extract_csrf_token()
                        if self.csrf_token:
                            print(f"✓ Successfully logged in to {controller_type} at {self.host} (CSRF token extracted)")
                        else:
                            print(f"✓ Successfully logged in to {controller_type} at {self.host}")
                    else:
                        print(f"✓ Successfully logged in to {controller_type} at {self.host}")

                    return True
                else:
                    last_error = f"{response.status_code} - {response.text}"
            except Exception as e:
                last_error = str(e)
                continue

        # If we get here, both attempts failed
        print(f"✗ Login failed on all endpoints. Last error: {last_error}")
        print(f"\nTroubleshooting tips:")
        print(f"  1. Verify username and password are correct")
        print(f"  2. Ensure you're using a LOCAL account (not Ubiquiti SSO/cloud)")
        print(f"  3. Check that the account has admin privileges")
        print(f"  4. Verify the controller IP/hostname: {self.host}")
        return False

    def _get_api_url(self, path: str) -> str:
        """
        Get the full API URL with correct prefix for controller type

        Args:
            path: API path (e.g., '/api/s/default/rest/routing')

        Returns:
            Full URL with correct prefix
        """
        if self.is_unifios:
            # UniFi OS uses /proxy/network prefix
            return f"{self.base_url}/proxy/network{path}"
        else:
            # Legacy controller uses base URL directly
            return f"{self.base_url}{path}"

    def logout(self) -> bool:
        """Logout from the UniFi Controller"""
        if not self.logged_in:
            return True

        logout_url = f"{self.base_url}/api/logout"
        if self.is_unifios:
            logout_url = f"{self.base_url}/api/auth/logout"

        try:
            response = self.session.post(logout_url)
            self.logged_in = False
            print("✓ Logged out successfully")
            return True
        except Exception as e:
            print(f"✗ Error during logout: {e}")
            return False

    def create_static_route(self,
                          network: str,
                          name: str,
                          nexthop: Optional[str] = None,
                          interface: Optional[str] = None,
                          distance: int = 1,
                          enabled: bool = True,
                          skip_duplicates: bool = True,
                          cached_routes: Optional[List[Dict]] = None,
                          cached_interface_id: Optional[str] = None) -> Optional[Dict]:
        """
        Create a static route

        Args:
            network: Destination network in CIDR notation (e.g., '10.0.0.0/24')
            name: Name/description for the route
            nexthop: Next hop IP address (gateway) - required if interface not specified
            interface: WAN interface name (e.g., 'wan', 'wan2') - required if nexthop not specified
            distance: Administrative distance (default: 1)
            enabled: Enable the route (default: True)
            skip_duplicates: Skip creation if route already exists (default: True)
            cached_routes: Optional pre-fetched routes list to avoid repeated API calls
            cached_interface_id: Optional pre-fetched interface ID to avoid repeated lookups

        Returns:
            Dict containing the created route data, or None if failed
            Returns special dict {'skipped': True} if duplicate was skipped
        """
        if not self.logged_in:
            print("✗ Not logged in. Please login first.")
            return None

        # Validate that either nexthop or interface is provided
        if not nexthop and not interface:
            print("✗ Either nexthop IP or interface must be specified")
            return None

        # Parse network to ensure it's valid CIDR
        if '/' not in network:
            print("✗ Network must be in CIDR notation (e.g., 10.0.0.0/24)")
            return None

        # Check for duplicate route (pass cached data for performance)
        if skip_duplicates and self.route_exists(
            network=network,
            nexthop=nexthop,
            interface=interface,
            cached_routes=cached_routes,
            cached_interface_id=cached_interface_id
        ):
            route_via = f"nexthop {nexthop}" if nexthop else f"interface {interface}"
            print(f"⊘ Route already exists: {network} via {route_via} (skipping)")
            return {'skipped': True}

        url = self._get_api_url(f"/api/s/{self.site}/rest/routing")

        # Build payload based on route type
        if interface:
            # For interface-based routes, we need the interface ID
            # Use cached interface ID if provided, otherwise fetch it
            interface_id = cached_interface_id if cached_interface_id is not None else self.get_interface_id(interface)
            if not interface_id:
                print(f"✗ Could not find interface '{interface}'. Route creation aborted.")
                return None

            # Get gateway device (required for UniFi OS)
            gateway = self.get_gateway_device()

            payload = {
                "enabled": enabled,
                "name": name,
                "type": "static-route",
                "static-route_interface": interface_id,
                "static-route_network": network,
                "static-route_type": "interface-route",
                "gateway_type": "default"
            }

            # Add gateway_device if available
            if gateway and gateway.get('mac'):
                payload["gateway_device"] = gateway['mac']

            route_via = f"interface {interface}"
        else:
            # For nexthop-based routes
            network_addr, prefix_len = network.split('/')
            netmask = self._prefix_to_netmask(int(prefix_len))

            payload = {
                "type": "static-route",
                "name": name,
                "static-route_network": network_addr,
                "static-route_type": "nexthop-route",
                "static-route_nexthop": nexthop,
                "static-route_distance": distance,
                "enabled": enabled,
                "pfSense_netmask": netmask
            }
            route_via = f"nexthop {nexthop}"

        try:
            # Add CSRF token header for UniFi OS
            headers = {}
            if self.is_unifios and self.csrf_token:
                headers['X-CSRF-Token'] = self.csrf_token

            response = self.session.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                result = response.json()
                print(f"✓ Static route created: {network} via {route_via} (name: {name})")
                return result
            else:
                print(f"✗ Failed to create route: {response.status_code} - {response.text}")
                if response.status_code == 403:
                    print(f"\nTroubleshooting 403 Forbidden:")
                    print(f"  1. Verify your account has 'Super Administrator' role")
                    print(f"  2. Check if there are any firewall rules blocking route creation")
                    print(f"  3. Ensure the gateway can manage routes (not in bridge mode)")
                    print(f"  4. Try creating a route manually via the UI to verify permissions")
                    print(f"\nDebug info:")
                    print(f"  - URL: {url}")
                    print(f"  - Controller type: {'UniFi OS' if self.is_unifios else 'Legacy'}")
                    print(f"  - Payload: {json.dumps(payload, indent=2)}")
                return None
        except Exception as e:
            print(f"✗ Error creating static route: {e}")
            return None

    def get_gateway_device(self) -> Optional[Dict]:
        """
        Get the gateway device information (MAC address, etc.)

        Returns:
            Gateway device dict with MAC and other info, or None if failed
        """
        if not self.logged_in:
            return None

        url = self._get_api_url(f"/api/s/{self.site}/stat/device")

        try:
            response = self.session.get(url)
            if response.status_code == 200:
                data = response.json()
                devices = data.get('data', [])
                # Find the gateway device (usually type 'ugw', 'udm', 'udr', etc.)
                for device in devices:
                    device_type = device.get('type', '')
                    if device_type in ['ugw', 'udm', 'udr', 'uxg']:
                        return {
                            'mac': device.get('mac'),
                            'type': device_type
                        }
                # If no specific gateway found, return first device
                if devices:
                    return {
                        'mac': devices[0].get('mac'),
                        'type': devices[0].get('type')
                    }
            return None
        except Exception:
            return None

    def get_site_id(self) -> Optional[str]:
        """
        Get the current site ID

        Returns:
            Site ID string, or None if failed
        """
        if not self.logged_in:
            return None

        # Try getting site_id from existing routes first
        routes = self.list_static_routes()
        if routes and len(routes) > 0:
            site_id = routes[0].get('site_id')
            if site_id:
                return site_id

        # Fallback: try getting from sites list
        url = self._get_api_url(f"/api/self/sites")

        try:
            response = self.session.get(url)
            if response.status_code == 200:
                data = response.json()
                sites = data.get('data', [])
                for site in sites:
                    if site.get('name') == self.site or site.get('desc') == self.site:
                        return site.get('_id')
                # If no match, return first site
                if sites:
                    return sites[0].get('_id')
            return None
        except Exception:
            return None

    def get_network_interfaces(self) -> Optional[List[Dict]]:
        """
        Get all network interfaces (WAN ports)

        Returns:
            List of interface dictionaries, or None if failed
        """
        if not self.logged_in:
            print("✗ Not logged in. Please login first.")
            return None

        url = self._get_api_url(f"/api/s/{self.site}/rest/networkconf")

        try:
            response = self.session.get(url)
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            else:
                print(f"✗ Failed to get interfaces: {response.status_code}")
                return None
        except Exception as e:
            print(f"✗ Error getting interfaces: {e}")
            return None

    def get_interface_id(self, interface_name: str) -> Optional[str]:
        """
        Get the interface ID from interface name (e.g., 'wan2' -> ID)

        Args:
            interface_name: Interface name like 'wan', 'wan2', etc.

        Returns:
            Interface ID string, or None if not found
        """
        interfaces = self.get_network_interfaces()
        if not interfaces:
            return None

        # Try to match by name or purpose
        interface_name_lower = interface_name.lower()

        for iface in interfaces:
            # Check various possible name fields
            iface_purpose = iface.get('purpose', '').lower()
            iface_name = iface.get('name', '').lower()
            iface_wan_type = iface.get('wan_type', '').lower()

            # Match wan, wan2, etc.
            if interface_name_lower in [iface_purpose, iface_name]:
                return iface.get('_id')

            # Special handling for wan/wan2/wan3
            if interface_name_lower == 'wan' and iface_purpose == 'wan':
                return iface.get('_id')
            elif interface_name_lower == 'wan2' and (iface_purpose == 'wan' or 'wan2' in iface_name):
                # For secondary WAN, might need additional logic
                if iface.get('wan_networkgroup') == 'WAN2' or 'wan2' in iface_name.lower():
                    return iface.get('_id')

        print(f"✗ Could not find interface '{interface_name}'")
        print(f"Available interfaces:")
        for iface in interfaces:
            print(f"  - {iface.get('name', 'unknown')} (purpose: {iface.get('purpose', 'unknown')}, ID: {iface.get('_id', 'unknown')})")

        return None

    def list_static_routes(self) -> Optional[List[Dict]]:
        """
        List all static routes

        Returns:
            List of route dictionaries, or None if failed
        """
        if not self.logged_in:
            print("✗ Not logged in. Please login first.")
            return None

        url = self._get_api_url(f"/api/s/{self.site}/rest/routing")

        try:
            response = self.session.get(url)
            if response.status_code == 200:
                routes = response.json()
                return routes.get('data', [])
            else:
                print(f"✗ Failed to list routes: {response.status_code}")
                return None
        except Exception as e:
            print(f"✗ Error listing routes: {e}")
            return None

    def route_exists(self,
                     network: str,
                     nexthop: Optional[str] = None,
                     interface: Optional[str] = None,
                     cached_routes: Optional[List[Dict]] = None,
                     cached_interface_id: Optional[str] = None) -> bool:
        """
        Check if a route already exists for the given network and gateway

        Args:
            network: Destination network in CIDR notation (e.g., '10.0.0.0/24')
            nexthop: Next hop IP address (gateway) to match
            interface: WAN interface name to match
            cached_routes: Optional pre-fetched routes list to avoid repeated API calls
            cached_interface_id: Optional pre-fetched interface ID to avoid repeated lookups

        Returns:
            bool: True if route exists, False otherwise
        """
        # Use cached routes if provided, otherwise fetch from API
        routes = cached_routes if cached_routes is not None else self.list_static_routes()
        if not routes:
            return False

        # Normalize the network for comparison
        # For nexthop routes, we need to compare just the network address
        if nexthop:
            # Extract network address from CIDR
            network_addr = network.split('/')[0] if '/' in network else network
        else:
            # For interface routes, compare the full CIDR
            network_addr = network

        for route in routes:
            if route.get('type') != 'static-route':
                continue

            route_type = route.get('static-route_type', '')
            route_network = route.get('static-route_network', '')

            # Check if nexthop-based route exists
            if nexthop and route_type == 'nexthop-route':
                route_nexthop = route.get('static-route_nexthop', '')
                # Compare network address and nexthop
                if route_network == network_addr and route_nexthop == nexthop:
                    return True

            # Check if interface-based route exists
            elif interface and route_type == 'interface-route':
                # Use cached interface ID if provided, otherwise fetch it
                interface_id = cached_interface_id if cached_interface_id is not None else self.get_interface_id(interface)
                route_interface = route.get('static-route_interface', '')
                # Compare full CIDR network and interface
                if route_network == network and route_interface == interface_id:
                    return True

        return False

    def delete_static_route(self, route_id: str) -> bool:
        """
        Delete a static route by ID

        Args:
            route_id: The route ID to delete

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.logged_in:
            print("✗ Not logged in. Please login first.")
            return False

        url = self._get_api_url(f"/api/s/{self.site}/rest/routing/{route_id}")

        try:
            response = self.session.delete(url)
            if response.status_code == 200:
                print(f"✓ Route {route_id} deleted successfully")
                return True
            else:
                print(f"✗ Failed to delete route: {response.status_code}")
                return False
        except Exception as e:
            print(f"✗ Error deleting route: {e}")
            return False

    @staticmethod
    def _prefix_to_netmask(prefix_len: int) -> str:
        """Convert CIDR prefix length to netmask"""
        mask = (0xffffffff >> (32 - prefix_len)) << (32 - prefix_len)
        return '.'.join([str((mask >> (24 - i * 8)) & 0xff) for i in range(4)])


def read_networks_from_file(filename: str) -> List[str]:
    """
    Read networks from a text file (one per line)

    Args:
        filename: Path to the file containing networks

    Returns:
        List of network strings in CIDR notation
    """
    networks = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith('#'):
                    networks.append(line)
        return networks
    except FileNotFoundError:
        print(f"✗ Error: File '{filename}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error reading file: {e}")
        sys.exit(1)


def get_encryption_key() -> bytes:
    """
    Get or create encryption key for password encryption

    Returns:
        Encryption key bytes
    """
    key_file = os.path.expanduser('~/.unifi_route_loader.key')

    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        # Generate new key
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
        os.chmod(key_file, 0o600)  # Secure permissions
        return key


def encrypt_password(password: str) -> str:
    """
    Encrypt a password for storage in config file

    Args:
        password: Plain text password

    Returns:
        Encrypted password string (base64 encoded)
    """
    key = get_encryption_key()
    f = Fernet(key)
    encrypted = f.encrypt(password.encode())
    return encrypted.decode()


def decrypt_password(encrypted_password: str) -> str:
    """
    Decrypt an encrypted password from config file

    Args:
        encrypted_password: Encrypted password string

    Returns:
        Plain text password
    """
    try:
        key = get_encryption_key()
        f = Fernet(key)
        decrypted = f.decrypt(encrypted_password.encode())
        return decrypted.decode()
    except Exception as e:
        print(f"✗ Error decrypting password: {e}")
        print(f"This may happen if the encryption key has changed.")
        print(f"You may need to regenerate your encrypted password.")
        sys.exit(1)


def load_config_file(config_path: str) -> Dict:
    """
    Load configuration from YAML file

    Args:
        config_path: Path to YAML config file

    Returns:
        Dictionary of configuration options
    """
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        if not config:
            print(f"✗ Error: Config file '{config_path}' is empty")
            sys.exit(1)

        # Decrypt password if it's encrypted
        if 'password_encrypted' in config:
            config['password'] = decrypt_password(config['password_encrypted'])
            del config['password_encrypted']

        return config
    except FileNotFoundError:
        print(f"✗ Error: Config file '{config_path}' not found")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"✗ Error parsing YAML config file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Error reading config file: {e}")
        sys.exit(1)



def main():
    """Main function with command line argument parsing"""

    parser = argparse.ArgumentParser(
        description='Create static routes on UniFi Controller from a file',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create routes using a nexthop IP address (will prompt for password)
  %(prog)s -f networks.txt -n 192.168.1.254 -r "VPN Route"

  # Create routes using a WAN interface (with password on command line)
  %(prog)s -f networks.txt -w wan2 -r "WAN2 Route" --password pass123

  # With custom distance
  %(prog)s -f networks.txt -n 10.0.0.1 -r "Office" -d 10

  # Using a config file
  %(prog)s --config config.yaml

Configuration:
  You must specify either --nexthop (IP address) or --wan-interface (interface name)
  Password will be prompted securely if not provided via --password
  Config file can contain all command line options in YAML format
        """
    )

    # Config file option
    parser.add_argument('--config',
                        help='Path to YAML configuration file')

    # Required arguments (not required if using config file)
    parser.add_argument('-f', '--file',
                        help='Text file containing networks in CIDR notation (one per line)')
    parser.add_argument('-r', '--route-name', dest='route_name',
                        help='Base name for routes (will append numbers: "Name 1", "Name 2", etc.)')

    # Gateway options (mutually exclusive group)
    gateway_group = parser.add_mutually_exclusive_group()
    gateway_group.add_argument('-n', '--nexthop',
                        help='Next hop IP address (gateway) for all routes')
    gateway_group.add_argument('-w', '--wan-interface', dest='wan_interface',
                        help='WAN interface name for all routes (e.g., "wan", "wan2")')

    # Optional arguments
    parser.add_argument('--host',
                        help='UniFi controller hostname or IP (default: 192.168.1.1)')
    parser.add_argument('--username',
                        help='Admin username (default: admin)')
    parser.add_argument('--password',
                        help='Admin password (will prompt if not provided)')
    parser.add_argument('--site',
                        help='Site name (default: default)')
    parser.add_argument('-d', '--distance', type=int,
                        help='Administrative distance for routes (default: 1)')
    parser.add_argument('--port', type=int,
                        help='Controller port (default: 443)')
    parser.add_argument('--list-only', action='store_true',
                        help='Only list existing routes without creating new ones')
    parser.add_argument('--debug', action='store_true',
                        help='Show detailed debug information including API responses')

    args = parser.parse_args()

    # Load config file if specified
    config = {}
    if args.config:
        config = load_config_file(args.config)

    # Merge config file with command line arguments (command line takes precedence)
    # Build final configuration by combining defaults, config file, and command line args
    final_config = {
        'host': '192.168.1.1',
        'username': 'admin',
        'site': 'default',
        'distance': 1,
        'port': 443,
        'list_only': False,
        'debug': False,
    }

    # Update with config file values
    final_config.update(config)

    # Update with command line arguments (only if explicitly provided)
    if args.file is not None:
        final_config['file'] = args.file
    if args.route_name is not None:
        final_config['route_name'] = args.route_name
    if args.nexthop is not None:
        final_config['nexthop'] = args.nexthop
    if args.wan_interface is not None:
        final_config['wan_interface'] = args.wan_interface
    if args.host is not None:
        final_config['host'] = args.host
    if args.username is not None:
        final_config['username'] = args.username
    if args.password is not None:
        final_config['password'] = args.password
    if args.site is not None:
        final_config['site'] = args.site
    if args.distance is not None:
        final_config['distance'] = args.distance
    if args.port is not None:
        final_config['port'] = args.port
    if args.list_only:
        final_config['list_only'] = args.list_only
    if args.debug:
        final_config['debug'] = args.debug

    # Validate required arguments
    if 'file' not in final_config:
        print("✗ Error: --file is required (or specify in config file)")
        sys.exit(1)
    if 'route_name' not in final_config:
        print("✗ Error: --route-name is required (or specify in config file)")
        sys.exit(1)
    if 'nexthop' not in final_config and 'wan_interface' not in final_config:
        print("✗ Error: Either --nexthop or --wan-interface is required (or specify in config file)")
        sys.exit(1)

    # Convert to namespace for backward compatibility
    class Config:
        pass

    args = Config()
    for key, value in final_config.items():
        setattr(args, key, value)

    # Set None for nexthop/wan_interface if not specified
    if not hasattr(args, 'nexthop'):
        args.nexthop = None
    if not hasattr(args, 'wan_interface'):
        args.wan_interface = None

    # Prompt for password if not provided
    if not args.password:
        args.password = getpass.getpass(f"Password for {args.username}@{args.host}: ")

    # Read networks from file
    print(f"Reading networks from '{args.file}'...")
    networks = read_networks_from_file(args.file)

    if not networks:
        print("✗ No networks found in file")
        sys.exit(1)

    print(f"Found {len(networks)} network(s) to process")

    # Initialize controller connection
    controller = UniFiController(
        host=args.host,
        username=args.username,
        password=args.password,
        site=args.site,
        port=args.port
    )

    # Login
    if not controller.login():
        sys.exit(1)

    try:
        if args.list_only:
            # List existing routes
            print("\nCurrent static routes:")
            routes = controller.list_static_routes()
            if routes:
                for route in routes:
                    if route.get('type') == 'static-route':
                        route_type = route.get('static-route_type', 'unknown')
                        if route_type == 'interface-route':
                            via = f"interface {route.get('static-route_interface')}"
                        else:
                            via = f"nexthop {route.get('static-route_nexthop')}"
                        print(f"  - {route.get('name')}: {route.get('static-route_network')} via {via}")

                        if args.debug:
                            print(f"    Full route data: {json.dumps(route, indent=6)}")
            else:
                print("  No static routes found")
                if args.debug:
                    print("\nThis could mean:")
                    print("  - No routes configured yet")
                    print("  - Account lacks permission to view routes")
                    print("  - Wrong site name (current: {})".format(args.site))
        else:
            # Determine gateway type
            if args.wan_interface:
                gateway_display = f"interface: {args.wan_interface}"
            else:
                gateway_display = f"nexthop: {args.nexthop}"

            # Pre-fetch data once for performance optimization
            print(f"\nFetching existing routes...")
            cached_routes = controller.list_static_routes()

            # Pre-fetch interface ID if using interface-based routing
            cached_interface_id = None
            if args.wan_interface:
                print(f"Resolving interface '{args.wan_interface}'...")
                cached_interface_id = controller.get_interface_id(args.wan_interface)
                if not cached_interface_id:
                    print(f"✗ Could not find interface '{args.wan_interface}'")
                    sys.exit(1)

            # Create routes for each network
            print(f"\nCreating routes with {gateway_display}")
            print(f"Base route name: '{args.route_name}'")
            print(f"Administrative distance: {args.distance}\n")

            success_count = 0
            skipped_count = 0
            for idx, network in enumerate(networks, start=1):
                route_name = f"{args.route_name} {idx}"
                result = controller.create_static_route(
                    network=network,
                    name=route_name,
                    nexthop=args.nexthop,
                    interface=args.wan_interface,
                    distance=args.distance,
                    cached_routes=cached_routes,
                    cached_interface_id=cached_interface_id
                )
                if result:
                    if result.get('skipped'):
                        skipped_count += 1
                    else:
                        success_count += 1

            print(f"\n✓ Successfully created {success_count}/{len(networks)} route(s)")
            if skipped_count > 0:
                print(f"⊘ Skipped {skipped_count} duplicate route(s)")

    finally:
        # Logout
        controller.logout()


if __name__ == "__main__":
    main()
