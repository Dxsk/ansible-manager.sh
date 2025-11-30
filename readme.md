# Ansible Manager

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.0-blue?style=flat-square)
![Shell](https://img.shields.io/badge/shell-bash-green?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-orange?style=flat-square)
![Maintenance](https://img.shields.io/badge/maintained-yes-brightgreen?style=flat-square)

**A powerful Bash wrapper for Ansible that simplifies vault management, playbook execution, and common operations with a single command.**

[Installation](#installation) •
[Quick Start](#quick-start) •
[Commands](#commands) •
[Configuration](#configuration) •
[Examples](#examples)

</div>

---

## Table of Contents

- [What is it?](#what-is-it)
- [Why use it?](#why-use-it)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Commands](#commands)
  - [Vault Commands](#vault-commands)
  - [Playbook Commands](#playbook-commands)
  - [Inventory Commands](#inventory-commands)
  - [Project Commands](#project-commands)
  - [Utility Commands](#utility-commands)
- [Options](#options)
- [Examples](#examples)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)

## What is it?

`ansible-manager` is a bash script that simplifies common Ansible operations:

| Feature | Description |
|:--------|:------------|
| **Vault Management** | Encrypt, decrypt, edit, view, rekey, diff vault files |
| **Playbook Execution** | Run playbooks with retry support and full options |
| **Inventory Tools** | Visualize inventory, test connectivity, SSH checks |
| **Project Scaffolding** | Initialize roles, collections, and project structures |
| **Code Quality** | Lint and syntax-check your playbooks |

---

## Why use it?

> **Because life is too short to:**
> - Remember all ansible-vault commands
> - Manually handle encryption/decryption
> - Waste time with complex commands
> - Type long ansible-playbook commands repeatedly

## Installation

```bash
# 1. Copy the script
sudo cp ansible-manager.sh /usr/local/bin/ansible-manager

# 2. Make it executable
sudo chmod +x /usr/local/bin/ansible-manager

# 3. (Optional) Install bash completion
ansible-manager completion | sudo tee /etc/bash_completion.d/ansible-manager > /dev/null
source /etc/bash_completion.d/ansible-manager
```

## Quick Start

```bash
# Check vault status
ansible-manager status

# Run a playbook
ansible-manager run site.yml

# Run with dry-run mode
ansible-manager run deploy.yml --check --diff

# Test connectivity
ansible-manager ping
```

## Prerequisites

<table>
<tr>
<td width="50%">

**Required**

- `ansible`
- `ansible-vault`
- `ansible-playbook`
- `openssl`
- `sha256sum`

</td>
<td width="50%">

**Optional**

- `ansible-lint` → `lint` command
- `ansible-galaxy` → `galaxy` command
- `ansible-inventory` → `inventory` command

</td>
</tr>
</table>

## Configuration

The script looks for configuration in these locations (first found wins):

| Priority | Location | Scope |
|:--------:|:---------|:------|
| 1 | `.ansible-manager.conf` | Project-specific |
| 2 | `~/.ansible-manager.conf` | User-specific |
| 3 | `/etc/ansible-manager.conf` | System-wide |

<details>
<summary><strong>View configuration options</strong></summary>

```bash
# Example .ansible-manager.conf

VAULT_FILE="group_vars/all/vault.yml"
VAULT_DIR="$HOME/.ans_vaults"
INVENTORY_FILE="inventory.yml"
PLAYBOOKS_DIR="playbooks"
ROLES_DIR="roles"
LOG_FILE="/var/log/ansible-manager.log"
```

</details>


## Commands

### Syntax

```bash
ansible-manager [global-options] <command> [arguments] [options]
```

### Global Options

| Option | Description |
|:-------|:------------|
| `-v` | Enable debug output |
| `-vv` | Enable trace output (more verbose) |
| `--log <file>` | Log output to specified file |

---

### Vault Commands

| Command | Description |
|:--------|:------------|
| `encrypt [file]` | Encrypt a vault file |
| `decrypt [file]` | Decrypt a vault file |
| `edit [file]` | Edit a vault file |
| `view [file]` | View vault content |
| `rekey [file]` | Change the vault password |
| `status [file]` | Show vault encryption status |
| `encrypt-string <string>` | Encrypt a string for inline use in playbooks |
| `diff <vault1> <vault2>` | Compare two vault files (decrypted diff) |

---

### Playbook Commands

| Command | Description |
|:--------|:------------|
| `run <playbook>` | Run a playbook |
| `secure-run <playbook>` | Run with automatic encryption handling |
| `retry <playbook>` | Re-run a playbook on previously failed hosts |
| `syntax-check <playbook>` | Check playbook syntax without executing |
| `list [directory]` | List available playbooks |

---

### Inventory Commands

| Command | Description |
|:--------|:------------|
| `ping` | Test connectivity with all machines |
| `inventory [list\|graph]` | Display parsed inventory |
| `facts <host>` | Gather facts from a specific host |
| `ssh-check [target]` | Verify SSH connectivity and configuration |

---

### Project Commands

| Command | Description |
|:--------|:------------|
| `init role <name>` | Create a new role with ansible-galaxy |
| `init collection <ns.name>` | Create a new collection with ansible-galaxy |
| `init project [name]` | Create a complete Ansible project structure |
| `galaxy [requirements.yml]` | Install roles/collections from requirements file |
| `lint [target]` | Run ansible-lint on playbooks |

---

### Utility Commands

| Command | Description |
|:--------|:------------|
| `genpass` | Generate a new vault password |
| `backup` | Create a backup of the vault password file |
| `completion` | Generate bash completion script |
| `version` | Show version information |
| `help` | Show help |

---

## Options

Options available for `run` and `secure-run` commands:

| Option | Description |
|:-------|:------------|
| `--check` | Run in check mode (dry-run) |
| `--diff` | Show differences when files are changed |
| `--limit <pattern>` | Limit execution to specific hosts or groups |
| `--tags <tags>` | Only run plays and tasks tagged with these values |
| `--skip-tags <tags>` | Skip plays and tasks tagged with these values |
| `-e, --extra-vars <vars>` | Set additional variables (`key=value` or `@file.yml`) |
| `-K, --ask-become-pass` | Ask for privilege escalation password |
| `-b, --become` | Run operations with become |
| `--vault <file>` | Specify vault file path |
| `-v` / `-vv` / `-vvv` / `-vvvv` | Increase Ansible verbosity level |

---

## Examples

<details>
<summary><strong>Basic Operations</strong></summary>

```bash
# Run a playbook
ansible-manager run site.yml

# Run with check mode and diff
ansible-manager run deploy.yml --check --diff

# Run on specific hosts with tags
ansible-manager run site.yml --limit webservers --tags "deploy,config"

# Run with extra variables
ansible-manager run deploy.yml -e "version=1.2.3" -e "@vars/production.yml"

# Run with sudo password prompt
ansible-manager run site.yml --ask-become-pass
```

</details>

<details>
<summary><strong>Vault Operations</strong></summary>

```bash
# Encrypt default vault
ansible-manager encrypt

# Encrypt specific vault file
ansible-manager encrypt group_vars/production/vault.yml

# Edit vault
ansible-manager edit

# View vault content
ansible-manager view

# Change vault password
ansible-manager rekey

# Check vault status
ansible-manager status

# Encrypt a string for inline use
ansible-manager encrypt-string "my_secret_password" --name db_password

# Compare two vault files
ansible-manager diff group_vars/dev/vault.yml group_vars/prod/vault.yml
```

</details>

<details>
<summary><strong>Inventory Operations</strong></summary>

```bash
# Test connectivity to all hosts
ansible-manager ping

# Test connectivity to specific group
ansible-manager ping --limit webservers

# Display inventory as list
ansible-manager inventory list

# Display inventory as graph
ansible-manager inventory graph

# Gather facts from a host
ansible-manager facts webserver01

# Check SSH connectivity and configuration
ansible-manager ssh-check
ansible-manager ssh-check webservers
```

</details>

<details>
<summary><strong>Project Management</strong></summary>

```bash
# Initialize a new role
ansible-manager init role my_new_role

# Initialize a new collection
ansible-manager init collection mycompany.mytools

# Initialize a complete project structure
ansible-manager init project my_ansible_project

# Install roles and collections from requirements.yml
ansible-manager galaxy

# Lint all playbooks
ansible-manager lint
```

</details>

<details>
<summary><strong>Retry Failed Hosts</strong></summary>

```bash
# After a playbook fails on some hosts, retry only failed ones
ansible-manager retry site.yml

# Retry with additional options
ansible-manager retry site.yml --check --diff
```

</details>

<details>
<summary><strong>Debugging</strong></summary>

```bash
# Run with debug output
ansible-manager -v run site.yml

# Run with trace output and logging
ansible-manager -vv --log ansible.log run site.yml

# Check playbook syntax
ansible-manager syntax-check site.yml

# List available playbooks
ansible-manager list
ansible-manager list playbooks/
```

</details>

---

## Security

> [!IMPORTANT]
> Never commit backup files or vault passwords to version control.

| Feature | Details |
|:--------|:--------|
| **Password Storage** | Vault passwords stored in `~/.ans_vaults/` with unique files per project |
| **Permissions** | Automatically set to `700` (directory) and `600` (files) |
| **Interrupt Safety** | `secure-run` re-encrypts vault even if interrupted (via trap) |
| **Backup Security** | Backup files created with `600` permissions |

---

## Important Notes

> [!NOTE]
> - The script must be run from the Ansible project root directory
> - Vault and inventory files must be present (or configured via config file)
> - Optional commands require their respective tools to be installed

> [!TIP]
> Use `ansible-manager list` to discover available playbooks in your project.

---

## Contributing

Contributions are welcome! Feel free to:

- Open an issue
- Submit a pull request
- Improve the documentation

---

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT). See the [LICENSE](./license) file for more details.

---

<div align="center">

**[Back to top](#ansible-manager)**

</div>
