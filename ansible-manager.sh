#!/bin/bash
#
# ansible-manager - Because typing ansible-vault commands gets old fast
#
# Author: Dxsk
# License: MIT
#

set -euo pipefail
IFS=$'\n\t'

SCRIPT_NAME=""
SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_NAME
readonly SCRIPT_VERSION="2.0"

readonly E_SUCCESS=0
readonly E_ERROR=1
readonly E_MISSING_DEPS=2
readonly E_INVALID_ARGS=3

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Defaults - override these in .ansible-manager.conf
VAULT_FILE="group_vars/all/vault.yml"
VAULT_DIR="$HOME/.ans_vaults"
INVENTORY_FILE="inventory.yml"
PLAYBOOKS_DIR="."
ROLES_DIR="roles"
LOG_FILE=""
VERBOSITY=0

readonly REQUIRED_COMMANDS=(
    "ansible"
    "ansible-vault"
    "ansible-playbook"
    "openssl"
    "sha256sum"
)

declare -a TEMP_FILES=()

# Used by cleanup trap to re-encrypt if we get interrupted
SECURE_RUN_WAS_ENCRYPTED=false
SECURE_RUN_VAULT_FILE=""

###############################################################################
# Logging
###############################################################################

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*" >&2
    [[ -n "$LOG_FILE" ]] && echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*" >&2
    [[ -n "$LOG_FILE" ]] && echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*" >&2
    [[ -n "$LOG_FILE" ]] && echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
}

log_debug() {
    if (( VERBOSITY >= 1 )); then
        echo -e "${BLUE}[DEBUG]${NC} $*" >&2
        [[ -n "$LOG_FILE" ]] && echo "[DEBUG] $(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
    fi
}

log_trace() {
    if (( VERBOSITY >= 2 )); then
        echo -e "${CYAN}[TRACE]${NC} $*" >&2
        [[ -n "$LOG_FILE" ]] && echo "[TRACE] $(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE"
    fi
}

die() {
    log_error "$*"
    exit ${E_ERROR}
}

###############################################################################
# Utilities
###############################################################################

# Safety net - if something goes wrong, we don't leave the vault decrypted
cleanup() {
    local exit_code=$?

    if [[ "$SECURE_RUN_WAS_ENCRYPTED" == true ]] && [[ -n "$SECURE_RUN_VAULT_FILE" ]]; then
        if [[ -f "$SECURE_RUN_VAULT_FILE" ]] && ! grep -q "\$ANSIBLE_VAULT" "$SECURE_RUN_VAULT_FILE" 2>/dev/null; then
            log_warn "Secure-run interrupted, re-encrypting vault..."
            ansible-vault encrypt "$SECURE_RUN_VAULT_FILE" --vault-password-file "$(get_vault_pass_file)" 2>/dev/null || true
        fi
    fi

    if (( ${#TEMP_FILES[@]} > 0 )); then
        log_debug "Cleaning up ${#TEMP_FILES[@]} temporary files..."
        for tmp_file in "${TEMP_FILES[@]}"; do
            [[ -f "$tmp_file" ]] && rm -f "$tmp_file" 2>/dev/null || true
        done
    fi

    exit $exit_code
}

load_config() {
    local config_files=(
        ".ansible-manager.conf"
        "$HOME/.ansible-manager.conf"
        "/etc/ansible-manager.conf"
    )

    for config_file in "${config_files[@]}"; do
        if [[ -f "$config_file" ]]; then
            log_debug "Loading configuration from $config_file"
            # shellcheck source=/dev/null
            source "$config_file"
            return 0
        fi
    done

    log_debug "No configuration file found, using defaults"
    return 0
}

check_dependencies() {
    local missing_deps=()

    for cmd in "${REQUIRED_COMMANDS[@]}"; do
        command -v "$cmd" >/dev/null 2>&1 || missing_deps+=("$cmd")
    done

    if (( ${#missing_deps[@]} > 0 )); then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        exit ${E_MISSING_DEPS}
    fi
}

check_optional_command() {
    local cmd="$1"
    command -v "$cmd" >/dev/null 2>&1 || die "Command '$cmd' is not installed. Please install it first."
}

init_vault_dir() {
    if [[ ! -d "$VAULT_DIR" ]]; then
        log_info "Creating vault directory at $VAULT_DIR..."
        mkdir -p "$VAULT_DIR"
        chmod 700 "$VAULT_DIR"
        log_info "Vault directory created with secure permissions"
    else
        chmod 700 "$VAULT_DIR" 2>/dev/null || log_warn "Could not update permissions on existing vault directory"
    fi
}

# Each project gets its own password file based on directory hash
generate_vault_id() {
    pwd | sha256sum | cut -c1-30
}

get_vault_pass_file() {
    echo "$VAULT_DIR/$(generate_vault_id)"
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
    local vault="$1"
    [[ -f "$vault" ]] || die "Vault file $vault does not exist"
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
    grep -q "\$ANSIBLE_VAULT" "$1"
}

create_temp_file() {
    local tmp_file
    tmp_file=$(mktemp)
    TEMP_FILES+=("$tmp_file")
    echo "$tmp_file"
}

parse_ansible_options() {
    local -n args_ref=$1
    shift

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --check)
                args_ref+=("--check")
                shift
                ;;
            --diff)
                args_ref+=("--diff")
                shift
                ;;
            --limit)
                [[ -z "${2-}" ]] && die "Error: --limit requires a pattern"
                args_ref+=("--limit" "$2")
                shift 2
                ;;
            --tags)
                [[ -z "${2-}" ]] && die "Error: --tags requires tag names"
                args_ref+=("--tags" "$2")
                shift 2
                ;;
            --skip-tags)
                [[ -z "${2-}" ]] && die "Error: --skip-tags requires tag names"
                args_ref+=("--skip-tags" "$2")
                shift 2
                ;;
            -e|--extra-vars)
                [[ -z "${2-}" ]] && die "Error: --extra-vars requires variables"
                args_ref+=("--extra-vars" "$2")
                shift 2
                ;;
            --ask-become-pass|-K)
                args_ref+=("--ask-become-pass")
                shift
                ;;
            --become|-b)
                args_ref+=("--become")
                shift
                ;;
            --vault)
                [[ -z "${2-}" ]] && die "Error: --vault requires a vault file path"
                VAULT_FILE="$2"
                shift 2
                ;;
            -v)     args_ref+=("-v"); shift ;;
            -vv)    args_ref+=("-vv"); shift ;;
            -vvv)   args_ref+=("-vvv"); shift ;;
            -vvvv)  args_ref+=("-vvvv"); shift ;;
            *)      die "Unknown option: $1" ;;
        esac
    done
}

show_help() {
    cat <<EOF
${GREEN}Ansible Manager v${SCRIPT_VERSION}${NC}
Usage: $SCRIPT_NAME [command] [playbook/host] [options]

${YELLOW}Vault Commands:${NC}
  encrypt         Encrypt the vault file
  decrypt         Decrypt the vault file
  edit            Edit the vault file
  view            View vault content
  rekey           Change the vault password
  status          Show vault encryption status
  encrypt-string  Encrypt a string for inline use in playbooks
  diff            Compare two vault files (decrypted diff)

${YELLOW}Playbook Commands:${NC}
  run             Run a playbook (requires playbook name)
  secure-run      Run with automatic encryption/decryption handling
  retry           Re-run a playbook on previously failed hosts
  syntax-check    Check playbook syntax without executing
  list            List available playbooks

${YELLOW}Inventory Commands:${NC}
  ping            Test connectivity with all inventory machines
  inventory       Display parsed inventory (list or graph)
  facts           Gather facts from a host
  ssh-check       Verify SSH connectivity and configuration

${YELLOW}Project Commands:${NC}
  init            Initialize a new role, collection, or project
  galaxy          Install roles/collections from requirements.yml
  lint            Run ansible-lint on playbooks

${YELLOW}Utility Commands:${NC}
  genpass         Generate/regenerate vault password file
  backup          Backup the vault password file
  completion      Generate bash completion script
  help            Show this help
  version         Show version information

${YELLOW}Common Options:${NC}
  --check       Run in check mode (dry-run)
  --diff        Show differences when files are changed
  --limit       Limit execution to specific hosts/groups
  --tags        Only run plays and tasks tagged with these values
  --skip-tags   Skip plays and tasks tagged with these values
  -e, --extra-vars  Set additional variables (key=value or @file.yml)
  -K, --ask-become-pass  Ask for privilege escalation password
  -b, --become  Run operations with become
  --vault       Specify vault file path (default: $VAULT_FILE)
  -v/-vv/-vvv   Increase verbosity level

${YELLOW}Configuration:${NC}
  The script looks for configuration in these locations (first found wins):
    1. .ansible-manager.conf (current directory)
    2. ~/.ansible-manager.conf (home directory)
    3. /etc/ansible-manager.conf (system-wide)

${YELLOW}Examples:${NC}
  $SCRIPT_NAME run site.yml --limit webservers --tags deploy
  $SCRIPT_NAME secure-run deploy.yml --check --diff
  $SCRIPT_NAME retry site.yml
  $SCRIPT_NAME ping --limit "web*"
  $SCRIPT_NAME ssh-check webservers
  $SCRIPT_NAME facts webserver01
  $SCRIPT_NAME encrypt-string "secret" --name api_key
  $SCRIPT_NAME diff group_vars/dev/vault.yml group_vars/prod/vault.yml
  $SCRIPT_NAME init role my_new_role
  $SCRIPT_NAME init project my_ansible_project
EOF
}

show_version() {
    echo -e "${GREEN}Ansible Manager${NC} v${SCRIPT_VERSION}"
    echo "Ansible version: $(ansible --version | head -1)"
}

###############################################################################
# Command handlers
###############################################################################

handle_encrypt() {
    local vault="${1:-$VAULT_FILE}"
    check_vault_file "$vault"
    check_vault_pass

    if is_vault_encrypted "$vault"; then
        log_warn "Vault file $vault is already encrypted"
        return 0
    fi

    log_info "Encrypting vault file $vault..."
    ansible-vault encrypt "$vault" --vault-password-file "$(get_vault_pass_file)"
    log_info "Vault encrypted successfully"
}

handle_decrypt() {
    local vault="${1:-$VAULT_FILE}"
    check_vault_file "$vault"
    check_vault_pass

    if ! is_vault_encrypted "$vault"; then
        log_warn "Vault file $vault is not encrypted"
        return 0
    fi

    log_info "Decrypting vault file $vault..."
    ansible-vault decrypt "$vault" --vault-password-file "$(get_vault_pass_file)"
    log_info "Vault decrypted successfully"
}

handle_edit() {
    local vault="${1:-$VAULT_FILE}"
    check_vault_file "$vault"
    check_vault_pass
    log_info "Editing vault file $vault..."
    ansible-vault edit "$vault" --vault-password-file "$(get_vault_pass_file)"
}

handle_view() {
    local vault="${1:-$VAULT_FILE}"
    check_vault_file "$vault"
    check_vault_pass
    log_info "Viewing vault content of $vault..."
    ansible-vault view "$vault" --vault-password-file "$(get_vault_pass_file)"
}

handle_rekey() {
    local vault="${1:-$VAULT_FILE}"
    check_vault_file "$vault"
    check_vault_pass

    is_vault_encrypted "$vault" || die "Vault file $vault is not encrypted. Encrypt it first."

    local old_pass_file new_pass_file
    old_pass_file=$(get_vault_pass_file)
    new_pass_file=$(create_temp_file)

    log_info "Generating new vault password..."
    openssl rand -base64 32 > "$new_pass_file"
    chmod 600 "$new_pass_file"

    log_info "Rekeying vault file $vault..."
    if ansible-vault rekey "$vault" \
        --vault-password-file "$old_pass_file" \
        --new-vault-password-file "$new_pass_file"; then
        cp "$new_pass_file" "$old_pass_file"
        chmod 600 "$old_pass_file"
        log_info "Vault rekeyed successfully with new password"
    else
        die "Failed to rekey vault"
    fi
}

handle_run() {
    local playbook="$1"
    shift
    local ansible_args=()

    parse_ansible_options ansible_args "$@"

    check_vault_file "$VAULT_FILE"
    check_vault_pass
    check_inventory_file
    [[ -f "$playbook" ]] || die "Playbook '$playbook' does not exist"

    log_info "Running playbook $playbook..."
    log_debug "Arguments: ${ansible_args[*]:-none}"

    ansible-playbook -i "$INVENTORY_FILE" \
        --vault-password-file "$(get_vault_pass_file)" \
        "${ansible_args[@]}" \
        "$playbook"
}

handle_secure_run() {
    local playbook="$1"
    shift
    local ansible_args=()
    local playbook_status

    parse_ansible_options ansible_args "$@"

    check_vault_file "$VAULT_FILE"
    check_vault_pass
    check_inventory_file
    [[ -f "$playbook" ]] || die "Playbook '$playbook' does not exist"

    SECURE_RUN_VAULT_FILE="$VAULT_FILE"

    if is_vault_encrypted "$VAULT_FILE"; then
        SECURE_RUN_WAS_ENCRYPTED=true
        log_warn "Vault is encrypted, temporary decryption..."
        ansible-vault decrypt "$VAULT_FILE" --vault-password-file "$(get_vault_pass_file)"
    fi

    log_info "Running playbook $playbook..."
    log_debug "Arguments: ${ansible_args[*]:-none}"

    set +e
    ansible-playbook -i "$INVENTORY_FILE" \
        --vault-password-file "$(get_vault_pass_file)" \
        "${ansible_args[@]}" \
        "$playbook"
    playbook_status=$?
    set -e

    if [[ "$SECURE_RUN_WAS_ENCRYPTED" == true ]]; then
        log_warn "Re-encrypting vault..."
        ansible-vault encrypt "$VAULT_FILE" --vault-password-file "$(get_vault_pass_file)"
        SECURE_RUN_WAS_ENCRYPTED=false
    fi

    return ${playbook_status}
}

handle_ping() {
    local ansible_args=()
    local was_encrypted=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --limit)
                [[ -z "${2-}" ]] && die "Error: --limit requires a pattern"
                ansible_args+=("--limit" "$2")
                shift 2
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done

    check_vault_file "$VAULT_FILE"
    check_vault_pass
    check_inventory_file

    if is_vault_encrypted "$VAULT_FILE"; then
        was_encrypted=true
        log_warn "Vault is encrypted, temporary decryption..."
        ansible-vault decrypt "$VAULT_FILE" --vault-password-file "$(get_vault_pass_file)"
    fi

    log_info "Testing connectivity with machines..."
    set +e
    ansible all -m ping -i "$INVENTORY_FILE" "${ansible_args[@]}"
    local ping_status=$?
    set -e

    if [[ "$was_encrypted" == true ]]; then
        log_warn "Re-encrypting vault..."
        ansible-vault encrypt "$VAULT_FILE" --vault-password-file "$(get_vault_pass_file)"
    fi

    return $ping_status
}

handle_status() {
    local vault="${1:-$VAULT_FILE}"

    if [[ ! -f "$vault" ]]; then
        log_error "Vault file $vault does not exist"
        return 1
    fi

    echo -e "${CYAN}Vault Status:${NC}"
    echo "  File: $vault"

    if is_vault_encrypted "$vault"; then
        echo -e "  Status: ${GREEN}Encrypted${NC}"
    else
        echo -e "  Status: ${YELLOW}Not encrypted${NC}"
    fi

    local vault_pass_file
    vault_pass_file=$(get_vault_pass_file)
    echo "  Password file: $vault_pass_file"

    if [[ -f "$vault_pass_file" ]]; then
        echo -e "  Password status: ${GREEN}Exists${NC}"
    else
        echo -e "  Password status: ${YELLOW}Not found${NC}"
    fi
}

handle_backup() {
    local vault_pass_file backup_file
    vault_pass_file=$(get_vault_pass_file)
    backup_file="vault_pass_$(generate_vault_id).backup"

    [[ -f "$vault_pass_file" ]] || die "No vault password file found to backup"

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

handle_syntax_check() {
    local playbook="$1"

    check_vault_pass
    check_inventory_file
    [[ -f "$playbook" ]] || die "Playbook '$playbook' does not exist"

    log_info "Checking syntax of $playbook..."
    if ansible-playbook -i "$INVENTORY_FILE" \
        --vault-password-file "$(get_vault_pass_file)" \
        --syntax-check "$playbook"; then
        log_info "Syntax check passed"
    else
        die "Syntax check failed"
    fi
}

handle_list() {
    local search_dir="${1:-$PLAYBOOKS_DIR}"

    log_info "Available playbooks in $search_dir:"
    echo

    local count=0
    while IFS= read -r -d '' playbook; do
        local name
        name=$(basename "$playbook")
        [[ "$name" == _* ]] && continue

        echo -e "  ${GREEN}•${NC} $playbook"
        ((count++))
    done < <(find "$search_dir" -maxdepth 2 -name "*.yml" -o -name "*.yaml" 2>/dev/null | grep -v "group_vars\|host_vars\|roles\|inventory\|requirements\|vault" | sort -z)

    echo
    log_info "Found $count playbook(s)"
}

handle_galaxy() {
    local requirements_file="${1:-requirements.yml}"
    local galaxy_args=()

    check_optional_command "ansible-galaxy"
    [[ -f "$requirements_file" ]] || die "Requirements file '$requirements_file' does not exist"

    if grep -q "^roles:" "$requirements_file" || ! grep -q "^collections:" "$requirements_file"; then
        log_info "Installing roles from $requirements_file..."
        ansible-galaxy role install -r "$requirements_file" --roles-path "${ROLES_DIR}" "${galaxy_args[@]}"
    fi

    if grep -q "^collections:" "$requirements_file"; then
        log_info "Installing collections from $requirements_file..."
        ansible-galaxy collection install -r "$requirements_file" "${galaxy_args[@]}"
    fi

    log_info "Galaxy dependencies installed successfully"
}

handle_lint() {
    local target="${1:-.}"

    check_optional_command "ansible-lint"

    log_info "Running ansible-lint on $target..."
    ansible-lint "$target"
}

handle_inventory() {
    local format="${1:-list}"

    check_optional_command "ansible-inventory"
    check_inventory_file
    check_vault_pass

    log_info "Displaying inventory ($format)..."

    case "$format" in
        list)
            ansible-inventory -i "$INVENTORY_FILE" \
                --vault-password-file "$(get_vault_pass_file)" \
                --list
            ;;
        graph)
            ansible-inventory -i "$INVENTORY_FILE" \
                --vault-password-file "$(get_vault_pass_file)" \
                --graph
            ;;
        *)
            die "Unknown inventory format: $format (use 'list' or 'graph')"
            ;;
    esac
}

handle_facts() {
    local host="$1"
    local was_encrypted=false

    [[ -z "$host" ]] && die "Host name required. Usage: $SCRIPT_NAME facts <hostname>"

    check_vault_file "$VAULT_FILE"
    check_vault_pass
    check_inventory_file

    if is_vault_encrypted "$VAULT_FILE"; then
        was_encrypted=true
        log_warn "Vault is encrypted, temporary decryption..."
        ansible-vault decrypt "$VAULT_FILE" --vault-password-file "$(get_vault_pass_file)"
    fi

    log_info "Gathering facts from $host..."
    set +e
    ansible "$host" -m setup -i "$INVENTORY_FILE"
    local facts_status=$?
    set -e

    if [[ "$was_encrypted" == true ]]; then
        log_warn "Re-encrypting vault..."
        ansible-vault encrypt "$VAULT_FILE" --vault-password-file "$(get_vault_pass_file)"
    fi

    return $facts_status
}

handle_encrypt_string() {
    local string="$1"
    local var_name="${2:-}"

    [[ -z "$string" ]] && die "String to encrypt is required. Usage: $SCRIPT_NAME encrypt-string <string> [--name <var_name>]"

    check_vault_pass

    log_info "Encrypting string..."
    if [[ -n "$var_name" ]]; then
        ansible-vault encrypt_string "$string" --vault-password-file "$(get_vault_pass_file)" --name "$var_name"
    else
        ansible-vault encrypt_string "$string" --vault-password-file "$(get_vault_pass_file)"
    fi
}

handle_retry() {
    local playbook="$1"
    shift
    local ansible_args=()
    local retry_file

    parse_ansible_options ansible_args "$@"

    [[ -f "$playbook" ]] || die "Playbook '$playbook' does not exist"

    # Find the retry file
    retry_file="${playbook%.yml}.retry"
    [[ -f "$retry_file" ]] || retry_file="${playbook%.yaml}.retry"
    [[ -f "$retry_file" ]] || die "No retry file found for $playbook (looked for ${playbook%.yml}.retry)"

    check_vault_file "$VAULT_FILE"
    check_vault_pass
    check_inventory_file

    local failed_hosts
    failed_hosts=$(cat "$retry_file")
    log_info "Retrying on failed hosts: $failed_hosts"

    ansible_args+=("--limit" "@$retry_file")

    ansible-playbook -i "$INVENTORY_FILE" \
        --vault-password-file "$(get_vault_pass_file)" \
        "${ansible_args[@]}" \
        "$playbook"

    # Clean up retry file on success
    if [[ $? -eq 0 ]]; then
        rm -f "$retry_file"
        log_info "Retry successful, removed $retry_file"
    fi
}

handle_init() {
    local init_type="${1:-}"
    local name="${2:-}"

    check_optional_command "ansible-galaxy"

    case "$init_type" in
        role)
            [[ -z "$name" ]] && die "Role name required. Usage: $SCRIPT_NAME init role <name>"
            log_info "Initializing new role: $name"
            ansible-galaxy role init "$name" --init-path "${ROLES_DIR}"
            log_info "Role created at ${ROLES_DIR}/$name"
            ;;
        collection)
            [[ -z "$name" ]] && die "Collection name required (format: namespace.name). Usage: $SCRIPT_NAME init collection <namespace.name>"
            log_info "Initializing new collection: $name"
            ansible-galaxy collection init "$name"
            log_info "Collection created: $name"
            ;;
        project)
            [[ -z "$name" ]] && name="."
            log_info "Initializing new Ansible project structure in $name"
            mkdir -p "$name"/{group_vars/all,host_vars,roles,playbooks,files,templates,inventory}

            # Create basic files
            [[ -f "$name/inventory/hosts.yml" ]] || cat > "$name/inventory/hosts.yml" <<'INVENTORY'
---
all:
  hosts:
    localhost:
      ansible_connection: local
  children:
    webservers:
      hosts:
    dbservers:
      hosts:
INVENTORY

            [[ -f "$name/ansible.cfg" ]] || cat > "$name/ansible.cfg" <<'ANSIBLECFG'
[defaults]
inventory = inventory/hosts.yml
roles_path = roles
host_key_checking = False
retry_files_enabled = True

[privilege_escalation]
become = False
become_method = sudo
become_ask_pass = False
ANSIBLECFG

            [[ -f "$name/group_vars/all/vault.yml" ]] || echo "---" > "$name/group_vars/all/vault.yml"
            [[ -f "$name/playbooks/site.yml" ]] || cat > "$name/playbooks/site.yml" <<'SITEYML'
---
- name: Main playbook
  hosts: all
  gather_facts: true
  roles: []
SITEYML

            [[ -f "$name/requirements.yml" ]] || cat > "$name/requirements.yml" <<'REQYML'
---
roles: []
collections: []
REQYML

            log_info "Project structure created successfully"
            echo -e "\n${CYAN}Created structure:${NC}"
            find "$name" -type f | head -20 | sed 's/^/  /'
            ;;
        *)
            echo -e "${YELLOW}Usage:${NC} $SCRIPT_NAME init <type> <name>"
            echo
            echo -e "${YELLOW}Types:${NC}"
            echo "  role        Create a new role with ansible-galaxy"
            echo "  collection  Create a new collection with ansible-galaxy"
            echo "  project     Create a complete project structure"
            echo
            echo -e "${YELLOW}Examples:${NC}"
            echo "  $SCRIPT_NAME init role my_role"
            echo "  $SCRIPT_NAME init collection myns.mycollection"
            echo "  $SCRIPT_NAME init project my_ansible_project"
            ;;
    esac
}

handle_diff() {
    local vault1="$1"
    local vault2="$2"

    [[ -z "$vault1" || -z "$vault2" ]] && die "Two vault files required. Usage: $SCRIPT_NAME diff <vault1> <vault2>"
    [[ -f "$vault1" ]] || die "Vault file $vault1 does not exist"
    [[ -f "$vault2" ]] || die "Vault file $vault2 does not exist"

    check_vault_pass

    local tmp1 tmp2
    tmp1=$(create_temp_file)
    tmp2=$(create_temp_file)

    log_info "Decrypting vaults for comparison..."

    # Decrypt both vaults to temp files
    if is_vault_encrypted "$vault1"; then
        ansible-vault view "$vault1" --vault-password-file "$(get_vault_pass_file)" > "$tmp1"
    else
        cp "$vault1" "$tmp1"
    fi

    if is_vault_encrypted "$vault2"; then
        ansible-vault view "$vault2" --vault-password-file "$(get_vault_pass_file)" > "$tmp2"
    else
        cp "$vault2" "$tmp2"
    fi

    log_info "Comparing $vault1 vs $vault2:"
    echo

    # Use diff with colors if available
    if command -v colordiff >/dev/null 2>&1; then
        colordiff -u "$tmp1" "$tmp2" --label "$vault1" --label "$vault2" || true
    else
        diff -u "$tmp1" "$tmp2" --label "$vault1" --label "$vault2" || true
    fi
}

handle_ssh_check() {
    local target="${1:-all}"
    local was_encrypted=false

    check_vault_file "$VAULT_FILE"
    check_vault_pass
    check_inventory_file

    if is_vault_encrypted "$VAULT_FILE"; then
        was_encrypted=true
        log_warn "Vault is encrypted, temporary decryption..."
        ansible-vault decrypt "$VAULT_FILE" --vault-password-file "$(get_vault_pass_file)"
    fi

    echo -e "${CYAN}SSH Configuration Check${NC}"
    echo

    log_info "Checking SSH connectivity and configuration for: $target"
    echo

    # Test raw SSH connection (bypasses Python)
    set +e
    ansible "$target" -i "$INVENTORY_FILE" -m raw -a "echo 'SSH OK: '\$(hostname)" 2>&1 | while read -r line; do
        if [[ "$line" == *"SUCCESS"* ]]; then
            echo -e "  ${GREEN}✓${NC} $line"
        elif [[ "$line" == *"UNREACHABLE"* ]] || [[ "$line" == *"FAILED"* ]]; then
            echo -e "  ${RED}✗${NC} $line"
        else
            echo "  $line"
        fi
    done
    local ssh_status=${PIPESTATUS[0]}
    set -e

    echo
    log_info "Checking SSH keys and agent..."

    # Check SSH agent
    if [[ -n "${SSH_AUTH_SOCK:-}" ]]; then
        echo -e "  ${GREEN}✓${NC} SSH agent is running"
        local key_count
        key_count=$(ssh-add -l 2>/dev/null | wc -l || echo "0")
        echo -e "  ${GREEN}✓${NC} $key_count key(s) loaded in agent"
    else
        echo -e "  ${YELLOW}!${NC} SSH agent not detected"
    fi

    # Check common SSH config issues
    if [[ -f ~/.ssh/config ]]; then
        echo -e "  ${GREEN}✓${NC} SSH config file exists"
    else
        echo -e "  ${YELLOW}!${NC} No SSH config file (~/.ssh/config)"
    fi

    if [[ "$was_encrypted" == true ]]; then
        log_warn "Re-encrypting vault..."
        ansible-vault encrypt "$VAULT_FILE" --vault-password-file "$(get_vault_pass_file)"
    fi

    return $ssh_status
}

handle_completion() {
    cat <<'COMPLETION'
# Bash completion for ansible-manager
# Install: source <(ansible-manager completion)
# Or: ansible-manager completion > /etc/bash_completion.d/ansible-manager

_ansible_manager_completions() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    commands="encrypt decrypt edit view rekey run secure-run retry ping status genpass backup syntax-check list galaxy lint inventory facts encrypt-string diff ssh-check init completion help version"

    case "$prev" in
        ansible-manager)
            COMPREPLY=( $(compgen -W "$commands" -- "$cur") )
            return 0
            ;;
        run|secure-run|syntax-check|retry)
            COMPREPLY=( $(compgen -f -X '!*.@(yml|yaml)' -- "$cur") )
            return 0
            ;;
        --limit|--tags|--skip-tags)
            return 0
            ;;
        --vault)
            COMPREPLY=( $(compgen -f -X '!*.yml' -- "$cur") )
            return 0
            ;;
        -e|--extra-vars)
            COMPREPLY=( $(compgen -f -- "$cur") )
            return 0
            ;;
        inventory)
            COMPREPLY=( $(compgen -W "list graph" -- "$cur") )
            return 0
            ;;
        galaxy)
            COMPREPLY=( $(compgen -f -X '!*.yml' -- "$cur") )
            return 0
            ;;
        lint)
            COMPREPLY=( $(compgen -d -- "$cur") $(compgen -f -X '!*.@(yml|yaml)' -- "$cur") )
            return 0
            ;;
        facts|ssh-check)
            return 0
            ;;
        diff)
            COMPREPLY=( $(compgen -f -X '!*.yml' -- "$cur") )
            return 0
            ;;
        init)
            COMPREPLY=( $(compgen -W "role collection project" -- "$cur") )
            return 0
            ;;
        *)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=( $(compgen -W "--check --diff --limit --tags --skip-tags --extra-vars --ask-become-pass --become --vault -v -vv -vvv -vvvv" -- "$cur") )
                return 0
            fi
            ;;
    esac
}

complete -F _ansible_manager_completions ansible-manager
COMPLETION
}

###############################################################################
# Main
###############################################################################

main() {
    trap cleanup EXIT
    trap 'die "Script interrupted"' INT TERM

    load_config
    init_vault_dir
    check_dependencies

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -v)     VERBOSITY=1; shift ;;
            -vv)    VERBOSITY=2; shift ;;
            --log)
                [[ -z "${2-}" ]] && die "Error: --log requires a file path"
                LOG_FILE="$2"
                shift 2
                ;;
            *)
                break
                ;;
        esac
    done

    if (( $# < 1 )); then
        show_help
        exit ${E_INVALID_ARGS}
    fi

    local command="$1"
    shift

    case "$command" in
        encrypt)
            local vault_target="$VAULT_FILE"
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --vault) vault_target="$2"; shift 2 ;;
                    *) vault_target="$1"; shift ;;
                esac
            done
            handle_encrypt "$vault_target"
            ;;
        decrypt)
            local vault_target="$VAULT_FILE"
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --vault) vault_target="$2"; shift 2 ;;
                    *) vault_target="$1"; shift ;;
                esac
            done
            handle_decrypt "$vault_target"
            ;;
        edit)
            local vault_target="$VAULT_FILE"
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --vault) vault_target="$2"; shift 2 ;;
                    *) vault_target="$1"; shift ;;
                esac
            done
            handle_edit "$vault_target"
            ;;
        view)
            local vault_target="$VAULT_FILE"
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --vault) vault_target="$2"; shift 2 ;;
                    *) vault_target="$1"; shift ;;
                esac
            done
            handle_view "$vault_target"
            ;;
        rekey)
            local vault_target="$VAULT_FILE"
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --vault) vault_target="$2"; shift 2 ;;
                    *) vault_target="$1"; shift ;;
                esac
            done
            handle_rekey "$vault_target"
            ;;
        run)
            [[ -z "${1-}" ]] && die "Error: Playbook name missing"
            handle_run "$@"
            ;;
        secure-run)
            [[ -z "${1-}" ]] && die "Error: Playbook name missing"
            handle_secure_run "$@"
            ;;
        ping)
            handle_ping "$@"
            ;;
        status)
            local vault_target="$VAULT_FILE"
            [[ -n "${1-}" ]] && vault_target="$1"
            handle_status "$vault_target"
            ;;
        genpass)
            generate_vault_pass
            ;;
        backup)
            handle_backup
            ;;
        syntax-check)
            [[ -z "${1-}" ]] && die "Error: Playbook name missing"
            handle_syntax_check "$1"
            ;;
        list)
            handle_list "${1:-}"
            ;;
        galaxy)
            handle_galaxy "${1:-requirements.yml}"
            ;;
        lint)
            handle_lint "${1:-.}"
            ;;
        inventory)
            handle_inventory "${1:-list}"
            ;;
        facts)
            [[ -z "${1-}" ]] && die "Error: Host name missing"
            handle_facts "$1"
            ;;
        encrypt-string)
            [[ -z "${1-}" ]] && die "Error: String to encrypt missing"
            local enc_string="$1"
            local enc_name=""
            shift
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --name) enc_name="$2"; shift 2 ;;
                    *) shift ;;
                esac
            done
            handle_encrypt_string "$enc_string" "$enc_name"
            ;;
        retry)
            [[ -z "${1-}" ]] && die "Error: Playbook name missing"
            handle_retry "$@"
            ;;
        init)
            handle_init "${1:-}" "${2:-}"
            ;;
        diff)
            handle_diff "${1:-}" "${2:-}"
            ;;
        ssh-check)
            handle_ssh_check "${1:-all}"
            ;;
        completion)
            handle_completion
            ;;
        help|--help|-h)
            show_help
            ;;
        version|--version)
            show_version
            ;;
        *)
            log_error "Unknown command: $command"
            show_help
            exit ${E_INVALID_ARGS}
            ;;
    esac
}

main "$@"
