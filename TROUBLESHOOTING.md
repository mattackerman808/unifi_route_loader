# Troubleshooting 401 Unauthorized Errors

## Updated Script
The script has been updated to automatically detect and support both:
- **Legacy UniFi Controllers** (using `/api/login`)
- **UniFi OS devices** like UDM, UDM-Pro, Cloud Key Gen2+ (using `/api/auth/login`)

## Most Common Cause: Using SSO/Cloud Account

The UniFi API **requires a local account**, not a Ubiquiti cloud/SSO account.

### How to Create a Local Admin Account

#### For UniFi OS (UDM, UDM-Pro, Cloud Key Gen2+):
1. Log into your UniFi OS console (https://your-controller-ip)
2. Go to **Settings** → **System** → **Advanced**
3. Under "Device Authentication", enable **Local Access**
4. Click **Create Local Admin**
5. Set a username (e.g., "admin") and password
6. Use these credentials with the script

#### For Legacy UniFi Controllers:
1. Log into your controller
2. Go to **Settings** → **Admins**
3. Click **Add Admin**
4. Select "Local" as the authentication method
5. Create username and password
6. Assign "Super Administrator" role
7. Use these credentials with the script

## Test Your Connection

Try running the script with just the list option to test authentication:

```bash
python3 create_static_routes.py \
  -f networks.txt \
  -n 192.168.1.1 \
  -r "Test" \
  --list-only
```

You should see:
```
✓ Successfully logged in to UniFi OS at 192.168.1.1
```
or
```
✓ Successfully logged in to Legacy UniFi Controller at 192.168.1.1
```

## Other Common Issues

### Wrong Controller IP/Hostname
**Symptoms:** Connection timeout or connection refused

**Solutions:**
- Verify you can reach the controller web interface at `https://your-ip`
- Make sure you're using the correct IP address
- If using a hostname, ensure DNS resolution works

### Wrong Port
**Symptoms:** Connection refused

**Solutions:**
- Default is 443 (HTTPS)
- Some setups use 8443
- Try: `--port 8443`

### Self-Signed Certificate Issues
**Symptoms:** SSL certificate errors

**Solutions:**
- The script disables SSL verification by default
- This is normal for self-signed certificates on UniFi controllers

### Wrong Site Name
**Symptoms:** 401 errors after successful login, or empty results

**Solutions:**
- Default site is "default"
- Check your site name in the controller UI
- Use: `--site your-site-name`

### Account Lacks Permissions
**Symptoms:** 401 or 403 errors

**Solutions:**
- Ensure the account has "Super Administrator" or full admin privileges
- Some read-only accounts can authenticate but cannot create routes

## Debug Steps

1. **Verify credentials:**
   ```bash
   # Try logging into the web interface with the same credentials
   # Open: https://your-controller-ip
   ```

2. **Check account type:**
   - If you login with an email address → That's SSO/cloud, create a local account
   - If you login with a username → That's local (correct)

3. **Test with curl:**
   ```bash
   # For Legacy Controller
   curl -k -X POST https://your-controller-ip/api/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"your-password"}'

   # For UniFi OS
   curl -k -X POST https://your-controller-ip/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"your-password"}'
   ```

   Expected: Status 200 with JSON response

4. **Review script output:**
   The updated script will show which endpoint it's trying and provide specific error messages

## Still Having Issues?

If you're still getting 401 errors after:
1. Creating a local admin account
2. Verifying the password is correct
3. Confirming the IP address is correct

Then check:
- Is 2FA enabled on the account? (The API doesn't support 2FA, use an account without it)
- Are there firewall rules blocking API access?
- Is the controller's management interface accessible?

## Script Updates

The script now:
- ✅ Tries both legacy and UniFi OS endpoints automatically
- ✅ Shows which controller type it detected
- ✅ Provides detailed troubleshooting tips on failure
- ✅ Uses correct API paths for UniFi OS (`/proxy/network` prefix)
