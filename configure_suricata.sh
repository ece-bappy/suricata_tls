#!/bin/bash

################################################################################
# Suricata Configuration Manager
# Universal script for T-Pot CE installations
# Manages eve-log filetype and event types persistently
################################################################################

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

################################################################################
# UTILITY FUNCTIONS
################################################################################

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

die() {
    log_error "$1"
    exit 1
}

################################################################################
# AUTO-DETECT T-POT INSTALLATION
################################################################################

detect_tpot_installation() {
    local tpot_path=""
    local candidate=""
    local -a candidates=("${HOME}/tpotce" "/opt/tpotce")

    # Under sudo, HOME may be /root even though T-Pot belongs to the invoking user.
    if [[ -n "${SUDO_USER:-}" ]]; then
        local sudo_user_home=""
        sudo_user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
        if [[ -n "$sudo_user_home" ]]; then
            candidates=("${sudo_user_home}/tpotce" "${candidates[@]}")
        fi
    fi

    while IFS= read -r candidate; do
        candidates+=("$candidate")
    done < <(find /home -mindepth 2 -maxdepth 2 -name tpotce -type d 2>/dev/null)

    for candidate in "${candidates[@]}"; do
        if [[ -f "${candidate}/data/suricata/suricata.yaml" ]]; then
            tpot_path="$candidate"
            break
        fi
    done
    
    if [[ -z "$tpot_path" ]] || [[ ! -d "$tpot_path" ]]; then
        die "T-Pot installation not found. Please ensure T-Pot CE is installed."
    fi
    
    echo "$tpot_path"
}

get_suricata_config_path() {
    local tpot_path="$1"
    local config_path="${tpot_path}/data/suricata/suricata.yaml"
    
    if [[ ! -f "$config_path" ]]; then
        die "Suricata config not found at: $config_path"
    fi
    
    echo "$config_path"
}

get_suricata_container_id() {
    local container_id=""
    container_id=$(docker ps --format "{{.ID}} {{.Names}}" 2>/dev/null | awk '$2 == "suricata" { print $1; exit }')

    if [[ -z "$container_id" ]]; then
        container_id=$(docker ps --format "{{.ID}} {{.Image}}" 2>/dev/null | awk '$2 ~ /telekom-security\/suricata/ { print $1; exit }')
    fi
    
    if [[ -z "$container_id" ]]; then
        log_warning "Suricata container not currently running" >&2
        return 1
    fi
    
    echo "$container_id"
}

get_log_directory() {
    local tpot_path="$1"
    echo "${tpot_path}/data/suricata/log"
}

################################################################################
# CONFIGURATION FUNCTIONS
################################################################################

validate_filetype() {
    local filetype="$1"
    local valid_types=("regular" "unix_stream" "unix_dgram" "syslog" "redis")
    
    for valid in "${valid_types[@]}"; do
        if [[ "$filetype" == "$valid" ]]; then
            return 0
        fi
    done
    
    die "Invalid filetype: $filetype. Valid options: ${valid_types[*]}"
}

validate_events() {
    local events="$1"
    local valid_events=("alert" "http" "dns" "tls" "ssh" "ftp" "smtp" "flow" "stats" "anomaly")
    
    IFS=',' read -ra event_array <<< "$events"
    for event in "${event_array[@]}"; do
        event=$(echo "$event" | xargs) # trim whitespace
        local found=0
        for valid in "${valid_events[@]}"; do
            if [[ "$event" == "$valid" ]]; then
                found=1
                break
            fi
        done
        if [[ $found -eq 0 ]]; then
            die "Invalid event type: $event. Valid options: ${valid_events[*]}"
        fi
    done
}

validate_tls_pcap_options() {
    local action="$1"
    local packet_count="$2"
    local size_limit="$3"
    local max_files="$4"
    local compression="$5"

    [[ "$action" == "enable" || "$action" == "disable" ]] || die "Invalid --tls-pcap action: $action. Use enable or disable."
    [[ "$packet_count" =~ ^[1-9][0-9]*$ ]] || die "--pcap-packets must be a positive integer"
    [[ "$size_limit" =~ ^[1-9][0-9]*(kb|mb|gb)$ ]] || die "--pcap-limit must include kb, mb, or gb (example: 100mb)"
    [[ "$max_files" =~ ^[1-9][0-9]*$ ]] || die "--pcap-max-files must be a positive integer"
    [[ "$compression" == "none" || "$compression" == "lz4" ]] || die "--pcap-compression must be none or lz4"
}

get_filename_for_filetype() {
    local filetype="$1"
    
    case "$filetype" in
        unix_stream|unix_dgram)
            echo "eve.sock"
            ;;
        regular|file)
            echo "eve.json"
            ;;
        syslog)
            echo "eve"
            ;;
        redis)
            echo "eve"
            ;;
        *)
            echo "eve.json"
            ;;
    esac
}

restore_original_config() {
    local config_path="$1"
    local tpot_path="$2"
    local original_config="${tpot_path}/docker/suricata/dist/suricata.yaml"

    if [[ ! -f "$original_config" ]]; then
        die "Original Suricata config not found at: $original_config"
    fi

    log_info "Restoring from Git checkout: $original_config"
    cp "$original_config" "$config_path"
    log_success "Original Suricata configuration restored"
}

################################################################################
# YAML MODIFICATION FUNCTIONS
################################################################################

get_eve_log_bounds() {
    local config_path="$1"

    awk '
        /^  - eve-log:$/ { start = NR; next }
        start && /^  - [^[:space:]]/ { print start, NR - 1; done = 1; exit }
        END { if (start && !done) print start, NR }
    ' "$config_path"
}

get_output_block_bounds() {
    local config_path="$1"
    local output_name="$2"

    awk -v output="$output_name" '
        $0 == "  - " output ":" { start = NR; next }
        start && /^  - [^[:space:]]/ { print start, NR - 1; done = 1; exit }
        END { if (start && !done) print start, NR }
    ' "$config_path"
}

set_yaml_key_in_range() {
    local config_path="$1"
    local start_line="$2"
    local end_line="$3"
    local key="$4"
    local value="$5"

    if sed -n "${start_line},${end_line}p" "$config_path" | grep -Eq "^[[:space:]]*#?[[:space:]]*${key}:"; then
        sed -i "${start_line},${end_line} s|^[[:space:]]*#\{0,1\}[[:space:]]*${key}:.*|      ${key}: ${value}|" "$config_path"
    else
        sed -i "${start_line}a\\      ${key}: ${value}" "$config_path"
    fi
}

configure_tls_pcap_output() {
    local config_path="$1"
    local enabled="$2"
    local size_limit="$3"
    local max_files="$4"
    local compression="$5"
    local start_line end_line

    read -r start_line end_line < <(get_output_block_bounds "$config_path" "pcap-log")
    [[ -n "${start_line:-}" && -n "${end_line:-}" ]] || die "pcap-log section not found"

    set_yaml_key_in_range "$config_path" "$start_line" "$end_line" enabled "$enabled"
    set_yaml_key_in_range "$config_path" "$start_line" "$end_line" filename tls-capture.pcap
    set_yaml_key_in_range "$config_path" "$start_line" "$end_line" limit "$size_limit"
    set_yaml_key_in_range "$config_path" "$start_line" "$end_line" max-files "$max_files"
    set_yaml_key_in_range "$config_path" "$start_line" "$end_line" compression "$compression"
    set_yaml_key_in_range "$config_path" "$start_line" "$end_line" mode normal
    set_yaml_key_in_range "$config_path" "$start_line" "$end_line" use-stream-depth no
    set_yaml_key_in_range "$config_path" "$start_line" "$end_line" conditional tag
}

install_tls_capture_rule() {
    local log_dir="$1"
    local packet_count="$2"
    local rule_path="${log_dir}/tls-capture.rules"

    printf '%s\n' "alert tls any any -> any any (msg:\"LOCAL TLS flow packet capture\"; flow:established,to_server; flowbits:isnotset,local.tls_capture_tagged; flowbits:set,local.tls_capture_tagged; tag:session,${packet_count},packets; sid:9000001; rev:1;)" > "$rule_path"
    chmod 0660 "$rule_path"
    chgrp "$(stat -c '%G' "$log_dir")" "$rule_path" 2>/dev/null || true
    log_success "TLS capture rule installed: $rule_path"
}

enable_tls_capture_rule() {
    local config_path="$1"
    local container_rule="/var/log/suricata/tls-capture.rules"

    if ! grep -Fxq "  - ${container_rule}" "$config_path"; then
        sed -i "/^rule-files:$/a\\  - ${container_rule}" "$config_path"
    fi
    log_success "TLS capture rule enabled"
}

disable_tls_capture_rule() {
    local config_path="$1"
    local container_rule="/var/log/suricata/tls-capture.rules"

    sed -i "\|^  - ${container_rule}$|d" "$config_path"
    log_success "TLS capture rule disabled"
}

get_eve_event_bounds() {
    local config_path="$1"
    local event_type="$2"
    local eve_start eve_end
    read -r eve_start eve_end < <(get_eve_log_bounds "$config_path")
    [[ -n "${eve_start:-}" && -n "${eve_end:-}" ]] || return 1

    awk -v first="$eve_start" -v last="$eve_end" -v event="$event_type" '
        NR < first || NR > last { next }
        $0 ~ "^[[:space:]]*- " event ":$" {
            start = NR
            item_column = match($0, /[^[:space:]]/)
            next
        }
        start && $0 ~ "^[[:space:]]*- [a-zA-Z0-9_-]+:" &&
            match($0, /[^[:space:]]/) == item_column {
            print start, NR - 1
            done = 1
            exit
        }
        END { if (start && !done) print start, last }
    ' "$config_path"
}

update_eve_log_filetype() {
    local config_path="$1"
    local filetype="$2"
    local filename="$3"
    local start_line end_line
    read -r start_line end_line < <(get_eve_log_bounds "$config_path")
    [[ -n "${start_line:-}" && -n "${end_line:-}" ]] || die "eve-log section not found"

    sed -i "${start_line},${end_line} s/^\([[:space:]]*filetype:[[:space:]]*\).*/\1$filetype/" "$config_path"
    sed -i "${start_line},${end_line} s/^\([[:space:]]*filename:[[:space:]]*\).*/\1$filename/" "$config_path"
    
    log_success "Updated filetype to: $filetype"
    log_success "Updated filename to: $filename"
}

enable_event_types() {
    local config_path="$1"
    local events="$2"
    
    # Convert comma-separated list to array
    IFS=',' read -ra event_array <<< "$events"
    
    # Create array of all possible event types in eve-log
    local all_events=("alert" "frame" "anomaly" "http" "dns" "tls" "ssh" "ftp" "smtp" "flow" "stats")
    
    # First, disable all event types
    for event in "${all_events[@]}"; do
        disable_event_type "$config_path" "$event"
    done
    
    # Then enable only selected event types
    for event in "${event_array[@]}"; do
        event=$(echo "$event" | xargs) # trim whitespace
        enable_event_type "$config_path" "$event"
    done
    
    local event_list=$(printf ', %s' "${event_array[@]}")
    event_list=${event_list:2}  # Remove leading comma and space
    log_success "Event types configured: $event_list"
}

enable_event_type() {
    local config_path="$1"
    local event_type="$2"
    local start_line end_line
    read -r start_line end_line < <(get_eve_event_bounds "$config_path" "$event_type")
    [[ -n "${start_line:-}" && -n "${end_line:-}" ]] || die "EVE event type not found: $event_type"

    if sed -n "${start_line},${end_line}p" "$config_path" | grep -q "^[[:space:]]*enabled:"; then
        sed -i "${start_line},${end_line} s/^\([[:space:]]*enabled:[[:space:]]*\).*/\1yes/" "$config_path"
    else
        sed -i "${start_line}a\\            enabled: yes" "$config_path"
    fi
}

disable_event_type() {
    local config_path="$1"
    local event_type="$2"
    local start_line end_line
    if ! read -r start_line end_line < <(get_eve_event_bounds "$config_path" "$event_type"); then
        return 0
    fi

    # Event types are enabled by default unless explicitly disabled.
    if [[ -n "$event_type" ]]; then
        if sed -n "${start_line},${end_line}p" "$config_path" | grep -q "^[[:space:]]*enabled:"; then
            sed -i "${start_line},${end_line} s/^\([[:space:]]*enabled:[[:space:]]*\).*/\1no/" "$config_path"
        else
            sed -i "${start_line}a\\            enabled: no" "$config_path"
        fi
    else
        # For other types:
        # 1. If they have an "enabled:" field, change yes to no
        # 2. If they don't have an "enabled:" field, add "enabled: no" on the next line
        
        if sed -n "${start_line},${end_line}p" "$config_path" | grep -A 5 "^[[:space:]]*- ${event_type}:" | grep -q "enabled:"; then
            # Has enabled field, just change it
            sed -i "${start_line},${end_line} { /^[[:space:]]*- ${event_type}:$/,/^[[:space:]]*- / { /enabled:/s/yes/no/ } }" "$config_path"
        else
            # No enabled field, add it after the event type line
            sed -i "${start_line},${end_line} { /^[[:space:]]*- ${event_type}:$/a\\            enabled: no
            }" "$config_path"
        fi
    fi
}

################################################################################
# CONTAINER MANAGEMENT
################################################################################

restart_suricata_container() {
    local container_id="$1"
    
    if [[ -z "$container_id" ]]; then
        log_warning "Suricata container not running. Skipping restart."
        return 0
    fi
    
    log_info "Restarting Suricata container: $container_id"
    docker restart "$container_id" > /dev/null 2>&1
    
    # Wait for container to be ready
    sleep 3
    
    log_success "Container restarted successfully"
}

validate_suricata_container_config() {
    local container_id="$1"

    if [[ -z "$container_id" ]]; then
        log_warning "Container is not running; skipping Suricata configuration validation"
        return 0
    fi

    log_info "Validating Suricata configuration and TLS capture rule..."
    if ! docker exec "$container_id" suricata -T -c /etc/suricata/suricata.yaml; then
        die "Suricata configuration validation failed; container was not restarted"
    fi
    log_success "Suricata configuration validation passed"
}

################################################################################
# DISPLAY FUNCTIONS
################################################################################

show_configuration() {
    local config_path="$1"
    local tpot_path="$2"
    local log_dir="$3"
    
    log_info "Current Suricata Configuration"
    echo "================================"
    
    # Get filetype - find line after "- eve-log:" and extract filetype value
    local filetype=$(grep -A 5 "^  - eve-log:" "$config_path" | grep "filetype:" | head -1 | sed 's/.*filetype:[[:space:]]*\([a-z_]*\).*/\1/')
    echo "Filetype: $filetype"
    
    # Get filename
    local filename=$(grep -A 5 "^  - eve-log:" "$config_path" | grep "filename:" | head -1 | sed 's/.*filename:[[:space:]]*\([a-z.]*\).*/\1/')
    echo "Filename (in container): /var/log/suricata/$filename"
    echo "Host path: ${log_dir}/${filename}"
    
    echo ""
    echo "Enabled Event Types (in eve-log):"
    
    # Check alert - it's enabled if it exists and doesn't have "enabled: no"
    if grep -q "^[[:space:]]*- alert:" "$config_path"; then
        if ! grep -A 2 "^[[:space:]]*- alert:" "$config_path" | grep -q "enabled: no"; then
            echo "  ✓ alert"
        fi
    fi
    
    # Check tls - enabled by default if present
    if grep -q "^[[:space:]]*- tls:" "$config_path"; then
        if ! grep -A 5 "^[[:space:]]*- tls:" "$config_path" | grep -q "enabled: no"; then
            echo "  ✓ tls"
        fi
    fi
    
    # Check http, dns, etc - enabled by default if present
    for event_type in http dns ssh ftp smtp; do
        if grep -q "^[[:space:]]*- ${event_type}:" "$config_path"; then
            if ! grep -A 5 "^[[:space:]]*- ${event_type}:" "$config_path" | grep -q "enabled: no"; then
                echo "  ✓ $event_type"
            fi
        fi
    done
    
    # Check frame, anomaly - need explicit "enabled: yes" since they default to no
    for event_type in frame anomaly; do
        if grep -q "^[[:space:]]*- ${event_type}:" "$config_path"; then
            if grep -A 2 "^[[:space:]]*- ${event_type}:" "$config_path" | grep -q "enabled: yes"; then
                echo "  ✓ $event_type"
            fi
        fi
    done
    
    echo "================================"
}

show_tls_pcap_configuration() {
    local config_path="$1"
    local log_dir="$2"
    local start_line end_line

    read -r start_line end_line < <(get_output_block_bounds "$config_path" "pcap-log")
    [[ -n "${start_line:-}" && -n "${end_line:-}" ]] || die "pcap-log section not found"

    local block
    block=$(sed -n "${start_line},${end_line}p" "$config_path")
    local enabled filename limit max_files compression conditional
    enabled=$(echo "$block" | sed -n 's/^[[:space:]]*enabled:[[:space:]]*//p' | head -1)
    filename=$(echo "$block" | sed -n 's/^[[:space:]]*filename:[[:space:]]*//p' | head -1)
    limit=$(echo "$block" | sed -n 's/^[[:space:]]*limit:[[:space:]]*//p' | head -1)
    max_files=$(echo "$block" | sed -n 's/^[[:space:]]*max-files:[[:space:]]*//p' | head -1)
    compression=$(echo "$block" | sed -n 's/^[[:space:]]*compression:[[:space:]]*//p' | head -1)
    conditional=$(echo "$block" | sed -n 's/^[[:space:]]*conditional:[[:space:]]*//p' | head -1)

    echo ""
    log_info "TLS Conditional PCAP Configuration"
    echo "================================"
    echo "Enabled: ${enabled:-no}"
    echo "Filename: ${filename:-N/A}"
    echo "Host directory: $log_dir"
    echo "File limit: ${limit:-N/A}"
    echo "Maximum files: ${max_files:-N/A}"
    echo "Compression: ${compression:-N/A}"
    echo "Conditional mode: ${conditional:-N/A}"
    if grep -Fxq "  - /var/log/suricata/tls-capture.rules" "$config_path"; then
        echo "TLS capture rule: enabled"
    else
        echo "TLS capture rule: disabled"
    fi
    echo "================================"
}

show_usage() {
    cat << 'EOF'
Suricata Configuration Manager for T-Pot CE

USAGE:
    ./configure_suricata.sh [COMMAND] [OPTIONS]

COMMANDS:
    --filetype TYPE     Set eve-log filetype (default: regular)
                        Options: regular, unix_stream, unix_dgram, syslog, redis
    
    --events EVENTS     Set event types to log (comma-separated, default: alert)
                        Options: alert, http, dns, tls, ssh, ftp, smtp, flow, stats, anomaly
    
    --show              Display current Suricata configuration
    
    --restore           Restore the original config from the T-Pot Git checkout

    --tls-pcap ACTION   Enable or disable bounded TLS conditional PCAP capture
                        Actions: enable, disable

TLS PCAP OPTIONS:
    --pcap-packets N        Packets tagged after TLS detection (default: 40)
    --pcap-limit SIZE       Maximum size of each capture file (default: 100mb)
    --pcap-max-files N      Maximum rotated capture files (default: 20)
    --pcap-compression TYPE Compression: none or lz4 (default: none)
    
    --help              Show this help message

EXAMPLES:
    # Configure for TLS and alerts with unix_stream socket
    ./configure_suricata.sh --filetype unix_stream --events tls,alert
    
    # Configure for regular file with multiple events
    ./configure_suricata.sh --filetype regular --events alert,http,dns
    
    # Show current configuration
    ./configure_suricata.sh --show
    
    # Restore the original configuration
    ./configure_suricata.sh --restore

    # Enable bounded TLS packet capture
    ./configure_suricata.sh --tls-pcap enable --pcap-packets 40 \
        --pcap-limit 100mb --pcap-max-files 20

    # Disable TLS packet capture
    ./configure_suricata.sh --tls-pcap disable

NOTES:
    - Configuration changes persist across container restarts
    - --restore uses docker/suricata/dist/suricata.yaml from the T-Pot checkout
    - TLS PCAP files are written to the T-Pot Suricata log directory
    - conditional: tag captures only flows selected by the local TLS rule
    - Socket files will be available at: /tpotce/data/suricata/log/eve.sock
    - Requires docker and T-Pot CE installation
EOF
}

################################################################################
# MAIN SCRIPT
################################################################################

main() {
    local filetype=""
    local events=""
    local show_config=false
    local restore_original=false
    local tls_pcap_action=""
    local pcap_packets=40
    local pcap_limit="100mb"
    local pcap_max_files=20
    local pcap_compression="none"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --filetype)
                filetype="$2"
                shift 2
                ;;
            --events)
                events="$2"
                shift 2
                ;;
            --show)
                show_config=true
                shift
                ;;
            --restore)
                restore_original=true
                shift
                ;;
            --tls-pcap)
                tls_pcap_action="$2"
                shift 2
                ;;
            --pcap-packets)
                pcap_packets="$2"
                shift 2
                ;;
            --pcap-limit)
                pcap_limit="$2"
                shift 2
                ;;
            --pcap-max-files)
                pcap_max_files="$2"
                shift 2
                ;;
            --pcap-compression)
                pcap_compression="$2"
                shift 2
                ;;
            --help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Check prerequisites
    if ! command -v docker &> /dev/null; then
        die "Docker is not installed or not in PATH"
    fi
    
    # Auto-detect T-Pot installation
    log_info "Detecting T-Pot installation..."
    local tpot_path=$(detect_tpot_installation)
    log_success "T-Pot found at: $tpot_path"
    
    local config_path=$(get_suricata_config_path "$tpot_path")
    local log_dir=$(get_log_directory "$tpot_path")
    
    log_success "Config file: $config_path"
    log_success "Log directory: $log_dir"
    
    # Handle --restore flag
    if [[ "$restore_original" == true ]]; then
        log_info "Restoring configuration..."
        restore_original_config "$config_path" "$tpot_path"
        
        local container_id=""
        container_id=$(get_suricata_container_id) || true
        restart_suricata_container "$container_id"
        
        log_success "Configuration restored and container restarted"
        return 0
    fi

    # Handle the independent TLS conditional-PCAP workflow.
    if [[ -n "$tls_pcap_action" ]]; then
        [[ -z "$filetype" && -z "$events" ]] || die "Do not combine --tls-pcap with --filetype or --events"
        validate_tls_pcap_options "$tls_pcap_action" "$pcap_packets" "$pcap_limit" "$pcap_max_files" "$pcap_compression"

        local container_id=""
        container_id=$(get_suricata_container_id) || true

        if [[ "$tls_pcap_action" == "enable" ]]; then
            log_info "Enabling bounded TLS conditional PCAP capture..."
            install_tls_capture_rule "$log_dir" "$pcap_packets"
            enable_tls_capture_rule "$config_path"
            configure_tls_pcap_output "$config_path" yes "$pcap_limit" "$pcap_max_files" "$pcap_compression"
        else
            log_info "Disabling TLS conditional PCAP capture..."
            configure_tls_pcap_output "$config_path" no "$pcap_limit" "$pcap_max_files" "$pcap_compression"
            disable_tls_capture_rule "$config_path"
        fi

        validate_suricata_container_config "$container_id"
        restart_suricata_container "$container_id"
        show_tls_pcap_configuration "$config_path" "$log_dir"
        return 0
    fi
    
    # Handle --show flag
    if [[ "$show_config" == true ]]; then
        show_configuration "$config_path" "$tpot_path" "$log_dir"
        show_tls_pcap_configuration "$config_path" "$log_dir"
        return 0
    fi
    
    # If no filetype or events specified, show usage
    if [[ -z "$filetype" ]] && [[ -z "$events" ]]; then
        log_error "No configuration specified"
        show_usage
        exit 1
    fi
    
    # Validate inputs
    if [[ -n "$filetype" ]]; then
        validate_filetype "$filetype"
    fi
    if [[ -n "$events" ]]; then
        validate_events "$events"
    fi
    
    # Set defaults
    [[ -z "$filetype" ]] && filetype="regular"
    [[ -z "$events" ]] && events="alert"
    
    # Get filename for filetype
    local filename=$(get_filename_for_filetype "$filetype")
    
    # Update configuration
    log_info "Updating configuration..."
    update_eve_log_filetype "$config_path" "$filetype" "$filename"
    enable_event_types "$config_path" "$events"
    
    # Restart container
    log_info "Applying changes..."
    local container_id=""
    container_id=$(get_suricata_container_id) || true
    restart_suricata_container "$container_id"
    
    # Show current configuration
    log_success "Configuration updated successfully!"
    echo ""
    show_configuration "$config_path" "$tpot_path" "$log_dir"
}

# Run main function
main "$@"
