# Security

## Reporting

Please report security issues privately to the project maintainer before opening a public GitHub issue. Do not include live tokens, payloads, customer data or exploitable production URLs in public reports.

## Security model

ZentWHook accepts untrusted inbound HTTP data and can make outbound HTTP requests. The two primary risk areas are secret/payload exposure and SSRF.

### Stored data

The persistent encryption key lives at `/data/encryption.key`. Endpoint authentication secrets, destination authentication secrets, event bodies/query strings/header values and delivery request/response details are encrypted before database storage where applicable. UI/search copies are masked.

Loss of `encryption.key` means encrypted records cannot be decrypted. Anyone who obtains both the database and this key can decrypt those records. Protect and back up both separately where possible.

### Outbound requests / SSRF

By default private, loopback and link-local targets are blocked. A destination may explicitly allow private or localhost access because self-hosted deployments often need internal APIs.

ZentWHook:

- accepts only `http` and `https`
- rejects URL-embedded credentials
- resolves DNS immediately before delivery
- rejects unsafe resolved addresses according to destination/global policy
- blocks link-local/metadata ranges
- does not follow HTTP redirects
- validates edited retry URLs again

For high-risk multi-user deployments, also apply network egress firewall rules. Application-level DNS checks cannot replace network isolation.

### Sessions and CSRF

Sessions are signed, expire after 12 hours, use HttpOnly and SameSite=Lax cookies, and use Secure cookies when `APP_BASE_URL` is HTTPS. Authenticated browser mutations require a CSRF token. Machine API access should use `API_TOKEN`.

### Passwords

Passwords are stored with scrypt using a unique random salt. The initial setup enforces a minimum length of 10 characters.

### Logs

Payloads and configured secrets are not intentionally written to container logs. Log messages use request/delivery identifiers and operational metadata.
