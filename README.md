# chum

**Chum** is a Keyfactor-inspired certificate lifecycle management tool written in Python.
It issues, renews, and deploys wildcard TLS certificates to heterogeneous devices
including HP printers, Proxmox VE nodes, OpenShift clusters, and Dell iDRAC interfaces.
New device types can be added by installing plugin packages from git.

---

## Features

| Feature | Description |
|---|---|
| 🔐 Certificate issuance | Generate keys, CSRs, self-signed or CA-signed certificates |
| 🔄 Renewal tracking | JSON store tracks every certificate's lifecycle status |
| 🌐 ACME / Let's Encrypt | Obtain wildcard certs via DNS-01 or DNS-PERSIST-01 challenge |
| 🔌 Plugin architecture | Install device plugins from git repos with one command |
| 🖨️ HP Printer | Deploy via the HP Embedded Web Server (EWS) |
| 🖥️ Proxmox VE | Deploy via the Proxmox REST API |
| ☁️ OpenShift | Deploy as a Kubernetes TLS Secret + IngressController patch |
| 🔧 Dell iDRAC | Deploy via the Redfish API |

---

## Installation

```bash
pip install chum
# or from source:
git clone https://github.com/albal/chum
cd chum
pip install -e ".[all]"
```

**Optional extras:**

| Extra | Packages | Purpose |
|---|---|---|
| `acme` | `acme`, `josepy` | Let's Encrypt wildcard certificates |
| `k8s` | `kubernetes` | OpenShift/Kubernetes kubeconfig support |
| `yaml` | `PyYAML` | YAML config file support |
| `all` | All of the above | Everything |

---

## Quick Start

```bash
# Initialise a local CA (optional – for in-house signing)
chum ca init --cn "My Company CA"

# Issue a wildcard certificate (self-signed)
chum cert issue --cn "*.example.com" --san example.com --self-signed --days 365

# List all managed certificates
chum cert list

# Show certificate details
chum cert show "*.example.com"

# Renew a certificate
chum cert renew "*.example.com" --days 365

# Deploy to Proxmox
chum deploy --plugin proxmox \
            --cert "*.example.com" \
            --host 10.0.0.1 \
            --username root@pam \
            --password secret \
            --node pve

# Deploy to Dell iDRAC
chum deploy --plugin idrac \
            --cert "*.example.com" \
            --host 10.0.0.2 \
            --username root \
            --password calvin

# Deploy to HP printer
chum deploy --plugin hp_printer \
            --cert "*.example.com" \
            --host 192.168.1.100 \
            --password admin

# Deploy to OpenShift
chum deploy --plugin openshift \
            --cert "*.example.com" \
            --api-url https://api.cluster.example.com:6443 \
            --token eyJhbGciOi...

# Verify deployment
chum verify --plugin proxmox \
            --cert "*.example.com" \
            --host 10.0.0.1

# List installed plugins
chum plugin list

# Install a community plugin from git
chum plugin install https://github.com/example/chum-plugin-fortinet.git
```

---

## Configuration

Chum looks for settings in `~/.chum/config.yaml` (YAML or JSON).
All settings can also be set via environment variables prefixed `CHUM_`.

```yaml
# ~/.chum/config.yaml

# Paths
store_path: ~/.chum/store.json
plugin_dir: ~/.chum/plugins
cert_dir:   ~/.chum/certs

# Local CA (optional)
ca_cert_path: ~/.chum/certs/ca/ca.crt
ca_key_path:  ~/.chum/certs/ca/ca.key

# ACME / Let's Encrypt (optional)
acme_email: admin@example.com
acme_staging: false
acme_challenge_type: dns-01  # or dns-persist-01
acme_persist_policy: wildcard  # optional: wildcard or subdomain
acme_persist_until: "2027-12-01T00:00:00Z"  # optional expiry

# Expiry warning threshold
expiry_warning_days: 30
```

| Environment variable | Description |
|---|---|
| `CHUM_CONFIG` | Path to config file |
| `CHUM_STORE_PATH` | Path to the certificate store JSON |
| `CHUM_CERT_DIR` | Directory where cert/key files are stored |
| `CHUM_PLUGIN_DIR` | Directory for external plugins |
| `CHUM_CA_CERT_PATH` | Path to the CA certificate |
| `CHUM_CA_KEY_PATH` | Path to the CA private key |
| `CHUM_ACME_EMAIL` | ACME registration email |
| `CHUM_ACME_STAGING` | Use Let's Encrypt staging (`true`/`false`) |
| `CHUM_ACME_CHALLENGE_TYPE` | ACME challenge type: `dns-01` or `dns-persist-01` |
| `CHUM_ACME_PERSIST_POLICY` | DNS-PERSIST-01 policy: `wildcard` or `subdomain` |
| `CHUM_ACME_PERSIST_UNTIL` | DNS-PERSIST-01 authorization expiry (ISO 8601) |
| `CHUM_EXPIRY_WARNING_DAYS` | Days before expiry to warn |

---

## DNS-PERSIST-01: Persistent DNS Validation

Chum supports the new [DNS-PERSIST-01](https://letsencrypt.org/2026/02/18/dns-persist-01.html)
challenge type introduced by Let's Encrypt in 2026. This allows certificate issuance and
renewal without requiring DNS record changes for each operation.

### Benefits

| Traditional DNS-01 | DNS-PERSIST-01 |
|---|---|
| Create/delete TXT record for each issuance | One-time TXT record setup |
| DNS propagation delays | No renewal-time DNS changes |
| DNS API credentials needed everywhere | Reduced credential exposure |
| Per-request automation complexity | Simplified automation at scale |

### How It Works

1. **One-time setup**: Create a persistent TXT record at `_validation-persist.<domain>`
2. **Ongoing use**: Certificate issuance and renewals verify the existing record
3. **No cleanup needed**: The record persists until you manually remove it

### Setup

```python
from chum.core.acme import AcmeClient

# Initialize and register
client = AcmeClient(email="admin@example.com")
account_key_pem = client.register()

# Generate the persistent DNS record (one-time)
record = client.generate_persist_record(
    domain="example.com",
    policy="wildcard",  # Authorize *.example.com
    persist_until="2027-12-01T00:00:00Z",  # Optional expiry
)

print(f"Create this DNS TXT record:")
print(f"  {record['fqdn']} = \"{record['value']}\"")
```

### Example TXT Record

```dns
_validation-persist.example.com.  IN TXT "acme-v02.api.letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/123456789; policy=wildcard"
```

### Obtaining Certificates

Once the persistent DNS record is in place:

```python
# No DNS hooks needed!
cert_pem, chain_pem, key_pem = client.obtain_wildcard_persist(
    domain="example.com",
)
```

### Security Considerations

⚠️ **Important**: DNS-PERSIST-01 does not re-validate domain control at each renewal.
If your DNS is compromised, an attacker could maintain certificate authorization until
you remove the TXT record.

- **Audit regularly**: Monitor your `_validation-persist.*` records
- **Rotate credentials**: Update authorization records when changing ACME accounts
- **Use expiry**: Set `persist_until` to limit authorization lifetime
- **Remove promptly**: Delete records when domains are decommissioned

---

## Plugin Architecture

### How plugins work

Every device plugin is a Python class that subclasses `chum.plugins.base.BasePlugin`
and implements four abstract methods:

```python
from chum.plugins.base import BasePlugin, DeployResult

class MyDevicePlugin(BasePlugin):
    NAME        = "mydevice"
    DESCRIPTION = "My Device"
    VERSION     = "1.0.0"

    def deploy(self, cert_pem, key_pem, chain_pem=None, **kwargs) -> DeployResult:
        ...

    def get_current_cert(self, **kwargs) -> bytes | None:
        ...

    def verify(self, cert_pem, **kwargs) -> bool:
        ...

    def revoke(self, **kwargs) -> DeployResult:
        ...
```

### Installing a plugin from git

External plugins live in `~/.chum/plugins/<name>/` and must include a `plugin.json` manifest:

```json
{
    "name": "mydevice",
    "version": "1.0.0",
    "description": "My Device Plugin",
    "module": "chum_mydevice.plugin",
    "class": "MyDevicePlugin"
}
```

Install with:
```bash
chum plugin install https://github.com/example/chum-plugin-mydevice.git
```

Update with:
```bash
chum plugin update mydevice
```

---

## Built-in Plugins

### HP Printer (`hp_printer`)

Deploys via the HP Embedded Web Server (EWS). Tested with HP LaserJet and OfficeJet
business-class printers.

| Parameter | Default | Description |
|---|---|---|
| `host` | **required** | Printer hostname or IP |
| `username` | `admin` | EWS administrator username |
| `password` | | EWS administrator password |
| `port` | `443` | HTTPS port |
| `verify_ssl` | `false` | Verify printer's TLS cert |

### Proxmox VE (`proxmox`)

Deploys via the Proxmox REST API (`PUT /api2/json/nodes/{node}/certificates/custom`).

| Parameter | Default | Description |
|---|---|---|
| `host` | **required** | Proxmox hostname or IP |
| `node` | `pve` | Proxmox node name |
| `username` | `root@pam` | User in `user@realm` format |
| `password` | | Password |
| `api_token` | | API token (`user@realm!id=secret`) – takes precedence |
| `port` | `8006` | API port |
| `verify_ssl` | `false` | Verify Proxmox TLS cert |

### OpenShift / Kubernetes (`openshift`)

Creates/updates a `kubernetes.io/tls` Secret and patches the default IngressController.

| Parameter | Default | Description |
|---|---|---|
| `api_url` | | API server URL (when not using kubeconfig) |
| `token` | | Bearer token |
| `kubeconfig` | `~/.kube/config` | Path to kubeconfig file |
| `context` | | Kubeconfig context |
| `namespace` | `openshift-ingress` | Target namespace |
| `secret_name` | `custom-router-cert` | TLS Secret name |
| `patch_router` | `true` | Patch the IngressController |
| `verify_ssl` | `true` | Verify API server TLS cert |

### Dell iDRAC (`idrac`)

Deploys via the Redfish API. Falls back to SCP (Server Configuration Profile) import
for older firmware.

| Parameter | Default | Description |
|---|---|---|
| `host` | **required** | iDRAC hostname or IP |
| `username` | `root` | iDRAC username |
| `password` | | iDRAC password |
| `port` | `443` | HTTPS port |
| `verify_ssl` | `false` | Verify iDRAC TLS cert |

---

## Development

```bash
# Clone
git clone https://github.com/albal/chum && cd chum

# Install in development mode with all extras
pip install -e ".[all]"
pip install pytest pytest-cov

# Run tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=chum --cov-report=term-missing
```

---

## License

MIT – see [LICENSE](LICENSE).
