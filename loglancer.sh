#!/bin/bash

set -u

VERSION="1.0.0"
AUTHOR="Security Researcher"
BANNER="LogLancer v${VERSION} - Web Log Analysis Tool"

declare -A COLORS=(
    ["RED"]='\033[0;31m'
    ["GREEN"]='\033[0;32m' 
    ["YELLOW"]='\033[1;33m'
    ["BLUE"]='\033[0;34m'
    ["PURPLE"]='\033[0;35m'
    ["CYAN"]='\033[0;36m'
    ["WHITE"]='\033[1;37m'
    ["NC"]='\033[0m'
)

declare -A THREAT_LEVELS=(
    ["CRITICAL"]=3
    ["HIGH"]=2
    ["MEDIUM"]=1
    ["LOW"]=0
    ["INFO"]=0
)

declare -A PATTERNS=(
    ["SQL_INJECTION"]="union.*select|select.*from|insert.*into|drop.*table|1=1|'or'1'='1"
    ["XSS"]="<script|javascript:|onerror=|onload=|alert\(|document\.cookie"
    ["PATH_TRAVERSAL"]="\.\./|\.\.\\|etc/passwd|boot\.ini|win\.ini"
    ["RCE"]="bash.*-i|python.*-c|perl.*-e|nc.*-e|wget.*-O|curl.*-o"
    ["LFI"]="include\(|require\(|include_once|require_once|\.\./\.\./"
    ["BF_LOGIN"]="login.*failed|authentication.*failed|invalid.*password"
    ["BF_DIR"]="admin.*404|wp-admin.*404|administrator.*404"
    ["SCANNERS"]="nikto|sqlmap|wpscan|nmap|burpsuite|acunetix"
    ["SHELL_UPLOAD"]="\.php\?|\.jsp\?|\.asp\?|cmd=|whoami|id|uname"
)

STATS_TOTAL=0
STATS_CRITICAL=0
STATS_HIGH=0
STATS_MEDIUM=0
STATS_LOW=0
STATS_INFO=0

THREATS=()
REPORT_DATA=()

print_color() {
    local color="$1"
    local message="$2"
    echo -e "${COLORS[$color]}${message}${COLORS["NC"]}"
}

print_banner() {
    print_color "CYAN" "╔══════════════════════════════════════════════════════════════╗"
    print_color "CYAN" "║                                                              ║"
    print_color "CYAN" "║  ${BANNER}║"
    print_color "CYAN" "║                                                              ║"  
    print_color "CYAN" "╚══════════════════════════════════════════════════════════════╝"
    echo
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  -f, --file FILE          Input log file to analyze
  -i, --stdin              Read from stdin (for tail -f)
  --nginx                  Auto-detect and analyze Nginx logs
  --apache                 Auto-detect and analyze Apache logs
  --live-mode SECONDS      Real-time monitoring with refresh interval
  --output FILE            Output report file (HTML/JSON)
  --help                   Show this help message
  --version                Show version

Examples:
  $0 -f /var/log/nginx/access.log
  $0 -f /var/log/apache2/access.log --output report.html
  tail -f /var/log/nginx/access.log | $0 -i --live-mode 5
  $0 --nginx --output scan_results.json

EOF
}

detect_webserver_logs() {
    local webserver="$1"
    local log_files=()
    
    case $webserver in
        nginx)
            log_files=(
                "/var/log/nginx/access.log"
                "/var/log/nginx/error.log" 
                "/usr/local/nginx/logs/access.log"
                "/etc/nginx/logs/access.log"
            )
            ;;
        apache)
            log_files=(
                "/var/log/apache2/access.log"
                "/var/log/apache2/error.log"
                "/var/log/httpd/access_log"
                "/var/log/httpd/error_log"
            )
            ;;
    esac
    
    for file in "${log_files[@]}"; do
        if [[ -f "$file" && -r "$file" ]]; then
            echo "$file"
            return 0
        fi
    done
    
    return 1
}

analyze_line() {
    local line="$1"
    local threats_found=()
    
    for pattern_name in "${!PATTERNS[@]}"; do
        if echo "$line" | grep -E -i --quiet "${PATTERNS[$pattern_name]}"; then
            threats_found+=("$pattern_name")
        fi
    done
    
    local status_code=$(echo "$line" | grep -E -o 'HTTP/[0-9.]+" ([0-9]{3})' | cut -d' ' -f2)
    if [[ -n "$status_code" ]]; then
        if [[ $status_code -ge 500 ]]; then
            threats_found+=("SERVER_ERROR_$status_code")
        elif [[ $status_code -ge 400 ]]; then
            threats_found+=("CLIENT_ERROR_$status_code")
        fi
    fi
    
    if [[ ${#threats_found[@]} -gt 0 ]]; then
        local threat_level="MEDIUM"
        local color="YELLOW"
        
        for threat in "${threats_found[@]}"; do
            case $threat in
                SQL_INJECTION|XSS|RCE|SHELL_UPLOAD)
                    threat_level="CRITICAL"
                    color="RED"
                    ;;
                LFI|PATH_TRAVERSAL)
                    threat_level="HIGH" 
                    color="RED"
                    ;;
                BF_LOGIN|BF_DIR|SCANNERS)
                    threat_level="MEDIUM"
                    color="YELLOW"
                    ;;
                SERVER_ERROR_*)
                    threat_level="HIGH"
                    color="RED"
                    ;;
                CLIENT_ERROR_*)
                    threat_level="MEDIUM"
                    color="YELLOW"
                    ;;
                *)
                    threat_level="LOW"
                    color="GREEN"
                    ;;
            esac
        done
        
        THREATS+=("$threat_level|$line")
        REPORT_DATA+=("{\"level\": \"$threat_level\", \"line\": \"${line//\"/\\\"}\"}")
        
        case $threat_level in
            "CRITICAL") ((STATS_CRITICAL++)) ;;
            "HIGH") ((STATS_HIGH++)) ;;
            "MEDIUM") ((STATS_MEDIUM++)) ;;
            "LOW") ((STATS_LOW++)) ;;
        esac
        
        ((STATS_TOTAL++))
        
        print_color "$color" "[$threat_level] $line"
        return 1
    fi
    
    return 0
}

process_file() {
    local file="$1"
    local line_number=0
    
    while IFS= read -r line; do
        ((line_number++))
        analyze_line "$line"
    done < "$file"
}

process_stdin() {
    local refresh_interval=${1:-0}
    
    if [[ $refresh_interval -gt 0 ]]; then
        while true; do
            clear
            print_banner
            process_stream
            sleep "$refresh_interval"
        done
    else
        process_stream
    fi
}

process_stream() {
    while IFS= read -r line; do
        analyze_line "$line"
    done
}

generate_html_report() {
    local output_file="$1"
    
    cat > "$output_file" << EOF
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LogLancer Security Report</title>
    <style>
        body { font-family: 'Courier New', monospace; background: #0a0a0a; color: #00ff00; margin: 20px; }
        .header { text-align: center; padding: 20px; border-bottom: 2px solid #00ff00; }
        .stats { background: #1a1a1a; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .threat { padding: 10px; margin: 5px 0; border-left: 4px solid; }
        .critical { border-color: #ff0000; background: #2a0000; }
        .high { border-color: #ff6b6b; background: #2a1a1a; }
        .medium { border-color: #ffeb3b; background: #2a2a00; }
        .low { border-color: #4caf50; background: #002a00; }
        .info { border-color: #2196f3; background: #001a2a; }
        .timestamp { color: #888; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ LogLancer Security Report</h1>
        <p>Generated on: $(date)</p>
    </div>
    
    <div class="stats">
        <h2>📊 Statistics</h2>
        <p>Total Threats: $STATS_TOTAL</p>
        <p>Critical: <span style="color: #ff0000;">$STATS_CRITICAL</span></p>
        <p>High: <span style="color: #ff6b6b;">$STATS_HIGH</span></p>
        <p>Medium: <span style="color: #ffeb3b;">$STATS_MEDIUM</span></p>
        <p>Low: <span style="color: #4caf50;">$STATS_LOW</span></p>
    </div>
    
    <h2>🔍 Detected Threats</h2>
EOF

    for threat in "${THREATS[@]}"; do
        IFS='|' read -r level line <<< "$threat"
        local class=$(echo "$level" | tr '[:upper:]' '[:lower:]')
        
        cat >> "$output_file" << EOF
    <div class="threat $class">
        <strong>[$level]</strong><br>
        <span class="line">${line//</&lt;}</span>
    </div>
EOF
    done

    cat >> "$output_file" << EOF
</body>
</html>
EOF
}

generate_json_report() {
    local output_file="$1"
    
    cat > "$output_file" << EOF
{
    "report": {
        "tool": "LogLancer",
        "version": "$VERSION",
        "generated_at": "$(date -Iseconds)",
        "statistics": {
            "total_threats": $STATS_TOTAL,
            "critical": $STATS_CRITICAL,
            "high": $STATS_HIGH,
            "medium": $STATS_MEDIUM,
            "low": $STATS_LOW
        },
        "threats": [
EOF

    for ((i=0; i<${#REPORT_DATA[@]}; i++)); do
        if [[ $i -gt 0 ]]; then
            echo "," >> "$output_file"
        fi
        echo -n "            ${REPORT_DATA[$i]}" >> "$output_file"
    done

    cat >> "$output_file" << EOF

        ]
    }
}
EOF
}

main() {
    local input_file=""
    local use_stdin=false
    local output_file=""
    local live_mode=0
    local webserver=""
    
    if [[ $# -eq 0 ]]; then
        usage
        exit 1
    fi
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f|--file)
                input_file="$2"
                shift 2
                ;;
            -i|--stdin)
                use_stdin=true
                shift
                ;;
            --nginx)
                webserver="nginx"
                shift
                ;;
            --apache)
                webserver="apache"
                shift
                ;;
            --live-mode)
                live_mode="$2"
                shift 2
                ;;
            --output)
                output_file="$2"
                shift 2
                ;;
            --help)
                usage
                exit 0
                ;;
            --version)
                echo "LogLancer v$VERSION"
                exit 0
                ;;
            *)
                print_color "RED" "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    print_banner
    
    if [[ -n "$webserver" ]]; then
        input_file=$(detect_webserver_logs "$webserver")
        if [[ $? -ne 0 ]]; then
            print_color "RED" "Could not find $webserver log files"
            exit 1
        fi
        print_color "GREEN" "Detected $webserver log file: $input_file"
    fi
    
    if [[ -n "$input_file" ]]; then
        if [[ ! -f "$input_file" || ! -r "$input_file" ]]; then
            print_color "RED" "Cannot read file: $input_file"
            exit 1
        fi
        process_file "$input_file"
    elif [[ "$use_stdin" == true ]]; then
        if [[ $live_mode -gt 0 ]]; then
            process_stdin "$live_mode"
        else
            process_stdin
        fi
    else
        print_color "RED" "No input source specified"
        exit 1
    fi
    
    print_color "CYAN" "\n📈 Summary:"
    print_color "GREEN" "Total lines processed: $STATS_TOTAL"
    print_color "RED" "Critical threats: $STATS_CRITICAL"
    print_color "RED" "High threats: $STATS_HIGH"
    print_color "YELLOW" "Medium threats: $STATS_MEDIUM"
    print_color "GREEN" "Low threats: $STATS_LOW"
    
    if [[ -n "$output_file" ]]; then
        case "${output_file##*.}" in
            html|HTML)
                generate_html_report "$output_file"
                print_color "GREEN" "HTML report generated: $output_file"
                ;;
            json|JSON)
                generate_json_report "$output_file"
                print_color "GREEN" "JSON report generated: $output_file"
                ;;
            *)
                print_color "RED" "Unsupported output format. Use .html or .json"
                exit 1
                ;;
        esac
    fi
}

trap 'print_color "RED" "\nOperation interrupted by user"; exit 1' INT

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
