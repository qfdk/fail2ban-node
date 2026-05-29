# fail2ban-node

A maintained Node.js client for [fail2ban](https://www.fail2ban.org), wrapping the `fail2ban-client` CLI.

## Why

Existing npm packages for fail2ban are unmaintained and rely on fragile Python pickle socket communication. This package uses the official `fail2ban-client` CLI — the stable, version-agnostic interface.

## Requirements

- Node.js >= 18
- `fail2ban-client` installed on the system (Linux only)

## Install

```bash
pnpm add fail2ban-node
# or
npm install fail2ban-node
```

## Usage

```js
const fail2ban = require('fail2ban-node');

// Check if fail2ban is running
const alive = await fail2ban.ping();

// Get all jails
const { total, list } = await fail2ban.status();
// { total: 2, list: ['sshd', 'nginx-http-auth'] }

// Get jail details
const jail = await fail2ban.jailStatus('sshd');
// {
//   currentlyFailed: 3,
//   totalFailed: 81,
//   fileList: ['/var/log/auth.log'],
//   currentlyBanned: 2,
//   totalBanned: 15,
//   bannedIPs: ['1.2.3.4', '5.6.7.8']
// }

// Ban an IP
await fail2ban.ban('sshd', '1.2.3.4');

// Unban an IP
await fail2ban.unban('sshd', '1.2.3.4');

// Reload configuration
await fail2ban.reload();

// Unban all IPs across all jails
await fail2ban.unbanAll();
```

## API

| Method | Description |
|--------|-------------|
| `ping()` | Check if fail2ban is running. Returns `boolean`. |
| `status()` | Get total jail count and jail list. |
| `jailStatus(jail)` | Get detailed status for a specific jail. |
| `ban(jail, ip)` | Ban an IP in a jail. |
| `unban(jail, ip)` | Unban an IP from a jail. |
| `reload()` | Reload fail2ban configuration. |
| `unbanAll()` | Unban all IPs across all jails. |

## License

GPL-2.0 — same as fail2ban itself.
