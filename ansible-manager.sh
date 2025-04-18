#!/bin/bash
#===================================================================================
# 
#         FILE: ansible-manager.sh
#
#        USAGE: ./ansible-manager.sh [command] [playbook] [options]
#
#  DESCRIPTION: Ansible management script to automate common operations
#               with vault, playbooks and inventory.
#
#      OPTIONS: See show_help() function or use --help
#       AUTHOR: dx
#      VERSION: 1.0
#     CREATED: 2025-04-18
#    REVISION: ---
#
# INSTALLATION: To install this script globally:
#              1. Copy the script to /usr/local/bin:
#                 sudo cp ansible-manager.sh /usr/local/bin/ansible-manager
#              2. Make it executable:
#                 sudo chmod +x /usr/local/bin/ansible-manager
#              3. Use it from anywhere:
#                 ansible-manager [command] [playbook]
#
#       NOTES: - For installation, make sure you have sudo permissions
#              - Script must be run from the Ansible project root directory
#              - Requires ansible, ansible-vault and openssl
#
#===================================================================================

# Exit on any error
set -euo pipefail
IFS=$'\n\t'

###################
# Constants
###################
readonly SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# Exit codes
readonly E_SUCCESS=0
readonly E_ERROR=1
readonly E_MISSING_DEPS=2
readonly E_INVALID_ARGS=3

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

# File paths
readonly VAULT_FILE="group_vars/proxmox/vault.yml"
readonly VAULT_DIR="$HOME/.ans_vaults"
readonly INVENTORY_FILE="inventory.yml"

# Required commands
readonly REQUIRED_COMMANDS=(
    "ansible"
    "ansible-vault"
    "ansible-playbook"
    "openssl"
    "sha256sum"
)

###################
# Logging functions
###################
log_info() {
    echo -e "${GREEN}[INFO]${NC} $*" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
}

die() {
    log_error "$*"
    exit ${E_ERROR}
}

###################
# Utility functions
###################
cleanup() {
    # Cleanup temporary files if they exist
    if [[ -n "${TEMP_FILES[@]+x}" ]]; then
        rm -f "${TEMP_FILES[@]}" 2>/dev/null || true
    fi
}

check_dependencies() {
    local missing_deps=()
    
    for cmd in "${REQUIRED_COMMANDS[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    if (( ${#missing_deps[@]} > 0 )); then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        exit ${E_MISSING_DEPS}
    fi
}

init_vault_dir() {
    if [[ ! -d "$VAULT_DIR" ]]; then
        log_info "Creating vault directory at $VAULT_DIR..."
        mkdir -p "$VAULT_DIR"
        chmod 700 "$VAULT_DIR"
        log_info "Vault directory created with secure permissions"
    else
        # Ensure permissions are correct even if directory exists
        chmod 700 "$VAULT_DIR" 2>/dev/null || log_warn "Could not update permissions on existing vault directory"
    fi
}

generate_vault_id() {
    local current_dir
    current_dir=$(pwd)
    echo "$current_dir" | sha256sum | cut -c1-30
}

get_vault_pass_file() {
    local vault_id
    vault_id=$(generate_vault_id)
    echo "$VAULT_DIR/$vault_id"
}

generate_vault_pass() {
    local vault_pass_file
    vault_pass_file=$(get_vault_pass_file)
    
    log_info "Generating new vault password..."
    if ! openssl rand -base64 32 > "$vault_pass_file"; then
        die "Failed to generate vault password"
    fi
    chmod 600 "$vault_pass_file" || die "Failed to set permissions on vault password file"
    log_info "New vault password generated at $vault_pass_file"
}

check_vault_file() {
    [[ -f "$VAULT_FILE" ]] || die "Vault file $VAULT_FILE does not exist"
}

check_vault_pass() {
    local vault_pass_file
    vault_pass_file=$(get_vault_pass_file)
    
    if [[ ! -f "$vault_pass_file" ]]; then
        log_warn "Password file $vault_pass_file does not exist, generating it..."
        generate_vault_pass
    fi
}

check_inventory_file() {
    [[ -f "$INVENTORY_FILE" ]] || die "Inventory file $INVENTORY_FILE does not exist"
}

is_vault_encrypted() {
    grep -q "\$ANSIBLE_VAULT" "$VAULT_FILE"
}

show_help() {
    cat <<EOF
Usage: $SCRIPT_NAME [command] [playbook] [options]

Commands:
  encrypt    - Encrypt the vault file
  decrypt    - Decrypt the vault file
  edit       - Edit the vault file
  view       - View vault content
  run        - Run a playbook (requires playbook name)
  secure-run - Run a playbook with automatic encryption/decryption handling
  ping       - Test connectivity with all inventory machines
  status     - Show vault status
  genpass    - Generate/regenerate vault password file
  backup     - Backup the vault password file to current directory
  help       - Show this help

Options:
  --check    - Run in check mode (dry-run) with run or secure-run commands
  --diff     - Show differences when files are changed
  --limit    - Limit execution to specific hosts or groups (e.g., "webservers" or "host1,host2")
EOF
}

###################
# Command handlers
###################
handle_encrypt() {
    check_vault_file
    check_vault_pass
    log_info "Encrypting vault file..."
    ansible-vault encrypt "$VAULT_FILE" --vault-password-file "$(get_vault_pass_file)"
}

handle_decrypt() {
    check_vault_file
    check_vault_pass
    log_info "Decrypting vault file..."
    ansible-vault decrypt "$VAULT_FILE" --vault-password-file "$(get_vault_pass_file)"
}

handle_edit() {
    check_vault_file
    check_vault_pass
    log_info "Editing vault file..."
    ansible-vault edit "$VAULT_FILE" --vault-password-file "$(get_vault_pass_file)"
}

handle_view() {
    check_vault_file
    check_vault_pass
    log_info "Viewing vault content..."
    ansible-vault view "$VAULT_FILE" --vault-password-file "$(get_vault_pass_file)"
}

handle_run() {
    local playbook="$1"
    local check_mode=false
    local diff_mode=false
    local limit_pattern=""
    local ansible_args=()
    
    # Parse options
    shift
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --check)
                check_mode=true
                ansible_args+=("--check")
                shift
                ;;
            --diff)
                diff_mode=true
                ansible_args+=("--diff")
                shift
                ;;
            --limit)
                if [[ -z "${2-}" ]]; then
                    die "Error: --limit requires a pattern"
                fi
                limit_pattern="$2"
                ansible_args+=("--limit" "$2")
                shift 2
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done
    
    check_vault_file
    check_vault_pass
    check_inventory_file
    
    log_info "Running playbook $playbook..."
    if [[ "$check_mode" == true ]]; then
        log_info "Running in check mode (dry-run)..."
    fi
    if [[ "$diff_mode" == true ]]; then
        log_info "Showing differences..."
    fi
    if [[ -n "$limit_pattern" ]]; then
        log_info "Limiting to: $limit_pattern"
    fi
    
    ansible-playbook -i "$INVENTORY_FILE" --vault-password-file "$(get_vault_pass_file)" "${ansible_args[@]}" "$playbook"
}

handle_secure_run() {
    local playbook="$1"
    local check_mode=false
    local diff_mode=false
    local limit_pattern=""
    local was_encrypted=false
    local playbook_status
    local ansible_args=()
    
    # Parse options
    shift
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --check)
                check_mode=true
                ansible_args+=("--check")
                shift
                ;;
            --diff)
                diff_mode=true
                ansible_args+=("--diff")
                shift
                ;;
            --limit)
                if [[ -z "${2-}" ]]; then
                    die "Error: --limit requires a pattern"
                fi
                limit_pattern="$2"
                ansible_args+=("--limit" "$2")
                shift 2
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done
    
    check_vault_file
    check_vault_pass
    check_inventory_file

    if is_vault_encrypted; then
        was_encrypted=true
        log_warn "Vault is encrypted, temporary decryption..."
        ansible-vault decrypt "$VAULT_FILE" --vault-password-file "$(get_vault_pass_file)"
    fi

    log_info "Running playbook $playbook..."
    if [[ "$check_mode" == true ]]; then
        log_info "Running in check mode (dry-run)..."
    fi
    if [[ "$diff_mode" == true ]]; then
        log_info "Showing differences..."
    fi
    if [[ -n "$limit_pattern" ]]; then
        log_info "Limiting to: $limit_pattern"
    fi

    if ! ansible-playbook -i "$INVENTORY_FILE" --vault-password-file "$(get_vault_pass_file)" "${ansible_args[@]}" "$playbook"; then
        playbook_status=${E_ERROR}
    else
        playbook_status=${E_SUCCESS}
    fi

    if [[ "$was_encrypted" == true ]]; then
        log_warn "Re-encrypting vault..."
        ansible-vault encrypt "$VAULT_FILE" --vault-password-file "$(get_vault_pass_file)"
    fi

    return ${playbook_status}
}

handle_ping() {
    local was_encrypted=false
    
    check_vault_file
    check_vault_pass
    check_inventory_file

    if is_vault_encrypted; then
        was_encrypted=true
        log_warn "Vault is encrypted, temporary decryption..."
        ansible-vault decrypt "$VAULT_FILE"
    fi

    log_info "Testing connectivity with all machines..."
    ansible all -m ping -i "$INVENTORY_FILE"

    if [[ "$was_encrypted" == true ]]; then
        log_warn "Re-encrypting vault..."
        ansible-vault encrypt "$VAULT_FILE"
    fi
}

handle_status() {
    check_vault_file
    if is_vault_encrypted; then
        log_info "Vault file is encrypted"
    else
        log_warn "Vault file is not encrypted"
    fi
}

handle_backup() {
    local vault_pass_file
    local backup_file
    vault_pass_file=$(get_vault_pass_file)
    backup_file="vault_pass_$(generate_vault_id).backup"
    
    if [[ ! -f "$vault_pass_file" ]]; then
        die "No vault password file found to backup"
    fi
    
    log_warn "WARNING: This will create a backup of your vault password in the current directory."
    log_warn "         Make sure to:"
    log_warn "         1. Never commit this file to version control"
    log_warn "         2. Delete it after use"
    log_warn "         3. Store it securely if you need to keep it"
    
    read -p "Do you want to continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log_info "Backup cancelled"
        exit ${E_SUCCESS}
    fi
    
    log_info "Creating backup of vault password file..."
    cp "$vault_pass_file" "$backup_file"
    chmod 600 "$backup_file"
    
    log_info "Backup created at: $backup_file"
    log_warn "Remember to delete this file after use!"
}

###################
# Main
###################
main() {
    # Set up trap for cleanup
    trap cleanup EXIT
    trap 'die "Script interrupted"' INT TERM

    # Initialize vault directory
    init_vault_dir

    # Check dependencies
    check_dependencies

    # Parse arguments
    if (( $# < 1 )); then
        show_help
        exit ${E_INVALID_ARGS}
    fi

    local command="$1"
    case "$command" in
        encrypt)     handle_encrypt ;;
        decrypt)     handle_decrypt ;;
        edit)        handle_edit ;;
        view)        handle_view ;;
        run)
            if [[ -z "${2-}" ]]; then
                die "Error: Playbook name missing"
            fi
            handle_run "$2" "${@:3}"
            ;;
        secure-run)
            if [[ -z "${2-}" ]]; then
                die "Error: Playbook name missing"
            fi
            handle_secure_run "$2" "${@:3}"
            ;;
        ping)        handle_ping ;;
        status)      handle_status ;;
        genpass)     generate_vault_pass ;;
        backup)      handle_backup ;;
        help)        show_help ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit ${E_INVALID_ARGS}
            ;;
    esac
}

# Execute main function
main "$@"
