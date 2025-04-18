# Ansible Manager

![Version](https://img.shields.io/badge/version-1.0-blue)
![Shell](https://img.shields.io/badge/shell-bash-green)

A utility script to simplify the management of your Ansible projects. Designed for humans who want to automate without the headache.

## 🚀 What is it?

`ansible-manager` is a bash script that simplifies common Ansible operations like:
- Vault management (encryption/decryption)
- Playbook execution
- Password management
- Connectivity testing

## 💡 Why use it?

Because life is too short to:
- Remember all ansible-vault commands
- Manually handle encryption/decryption
- Waste time with complex commands

## 🛠 Installation

```bash
# 1. Copy the script
sudo cp ansible-manager.sh /usr/local/bin/ansible-manager

# 2. Make it executable
sudo chmod +x /usr/local/bin/ansible-manager
```

## 📋 Prerequisites

- Ansible
- ansible-vault
- openssl
- An existing Ansible project

## 🎯 Usage

```bash
ansible-manager [command] [playbook]
```

### Available Commands

| Command | Description |
|----------|-------------|
| `encrypt` | Encrypts the vault file |
| `decrypt` | Decrypts the vault file |
| `edit` | Edits the vault file |
| `view` | Views vault content |
| `run` | Runs a playbook |
| `secure-run` | Runs a playbook with automatic encryption handling |
| `ping` | Tests connectivity with all machines |
| `status` | Shows vault status |
| `genpass` | Generates a new vault password |
| `backup` | Creates a backup of the vault password file in the current directory |
| `help` | Shows help |

### Available Options

| Option | Description |
|--------|-------------|
| `--check` | Run in check mode (dry-run) |
| `--diff` | Show differences when files are changed |
| `--limit "pattern"` | Limit execution to specific hosts or groups |

## 🔒 Security

- Vault passwords are stored in `~/.ans_vaults/` with unique files per project
- Permissions are automatically adjusted (700 for directory, 600 for files)
- Encryption is handled securely
- Backup files are created with secure permissions (600)
- ⚠️ **IMPORTANT**: Never commit backup files to version control

## 📝 Important Notes

- The script must be run from the Ansible project root directory
- Vault and inventory files must be present
- The script automatically handles encryption/decryption when needed
- Backup files should be deleted after use or stored securely
- Backup files are named with the project's unique ID for easy identification

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Open an issue
- Submit a pull request
- Improve the documentation

## 📜 License

This project is licensed under the [Unlicense](https://unlicense.org/). See the [LICENSE](./license) file for more details.
