EDC_API_URL=http://127.0.0.1:8000/
EDC_API_TOKEN="46314d52b9e70892ca5179ff85d7f7a9d982c344"
operator=kali1
function edc_token() {
    # --- Configuration Check ---
    if [[ -z "$EDC_API_URL" ]]; then
        echo "Error: EDC_API_URL environment variable is not set." >&2
        return 1
    fi
    if ! command -v curl &> /dev/null; then
        echo "Error: curl command not found. Please install curl." >&2
        return 1
    fi
    if ! command -v jq &> /dev/null; then
        echo "Error: jq command not found. Please install jq." >&2
        return 1
    fi

    # --- Prompt for Credentials ---
    local username
    local password
    read -p "Enter EDC Username: " username
    read -sp "Enter EDC Password: " password
    echo # Add a newline after hidden password input

    if [[ -z "$username" ]] || [[ -z "$password" ]]; then
        echo "Error: Username and password cannot be empty." >&2
        return 1
    fi

    # --- Construct JSON Payload ---
    local json_payload
    json_payload=$(jq -n --arg user "$username" --arg pass "$password" \
        '{username: $user, password: $pass}')

    # --- API Endpoint ---
    local base_url="${EDC_API_URL%/}"
    local token_url="${base_url}/api/get-token/"

    echo "Requesting token from ${token_url} for user ${username}..."

    # --- POST Request - Capture Status Code and Body Separately ---
    local response_body
    local http_code

    # Capture the HTTP status code specifically
    # -s silent, -L follow redirects, -o /dev/null discard body, -w write status code
    http_code=$(curl -s -L -o /dev/null -w '%{http_code}' \
        -X POST \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json' \
        -d "$json_payload" \
        "${token_url}")

    # Check curl's exit status ($?) to see if the command itself failed (e.g., connection refused)
    local curl_exit_status=$?
    if [[ "$curl_exit_status" -ne 0 ]]; then
         echo "Error: curl command failed with exit status ${curl_exit_status}. Could not connect?" >&2
         # Use the exit status or default to 000 if http_code wasn't captured
         http_code=${http_code:-000}
         # Try to get error message from curl if possible (might be empty)
         response_body=$(curl -s -L \
            -X POST \
            -H 'Content-Type: application/json' \
            -H 'Accept: application/json' \
            -d "$json_payload" \
            "${token_url}" 2>&1 ) # Capture stderr too this time
         echo "Curl Error Output (if any): ${response_body}" >&2

    # Check the HTTP status code returned by the server
    elif [[ "$http_code" -eq 200 ]]; then
        # If OK, run curl again to get the actual response body
        response_body=$(curl -s -L \
            -X POST \
            -H 'Content-Type: application/json' \
            -H 'Accept: application/json' \
            -d "$json_payload" \
            "${token_url}")

        local token
        token=$(echo "$response_body" | jq -r '.token')
        if [[ -n "$token" && "$token" != "null" ]]; then
            echo "Success! Token obtained:"
            echo "$token"
            echo "You can now set it as an environment variable:"
            echo "export EDC_API_TOKEN=\"${token}\""
            return 0 # Indicate success
        else
            echo "Error: Token request successful (HTTP 200), but no token found in response." >&2
            echo "Response Body:" >&2
            echo "$response_body" | jq '.' >&2
            return 1 # Indicate failure
        fi
    # Handle other non-200 HTTP codes
    else
        # Run curl again to get the error response body for display
        response_body=$(curl -s -L \
            -X POST \
            -H 'Content-Type: application/json' \
            -H 'Accept: application/json' \
            -d "$json_payload" \
            "${token_url}")
        echo "Error: Failed to obtain token (HTTP ${http_code})." >&2
        echo "Response Body:" >&2
        # Try to pretty print, ignore jq error if body isn't JSON
        echo "$response_body" | jq '.' 2>/dev/null || echo "$response_body" >&2
        return 1 # Indicate failure
    fi

    # This part is now reached only on curl command failure before HTTP check
    return 1

}

function log {
    # Assume 'operator' variable is set correctly in your environment
    # Alternatively, get username: operator=$(whoami)
    if [[ -z "$operator" ]]; then
        echo "Warning: 'operator' variable not set, using 'unknown'." >&2
        operator="unknown"
    fi
    local sip
    # Ensure my_ip function exists or replace with alternative
    if command -v my_ip &> /dev/null; then
        sip=$(my_ip)
    else
        echo "Warning: my_ip function not found, using default IP." >&2
        sip="127.0.0.1" # Default or use other method
    fi
    local shost
    shost=$(hostname)
    local tool="terminal" # Hardcoded tool

    # --- Config Checks ---
    if [[ -z "$EDC_API_URL" ]]; then echo "Error: EDC_API_URL not set." >&2; return 1; fi
    if [[ -z "$EDC_API_TOKEN" ]]; then echo "Error: EDC_API_TOKEN not set." >&2; return 1; fi
    if [[ $# -lt 1 ]]; then echo "Usage: log -d nmap -c 'your command here'" >&2; return 1; fi
    if ! command -v curl &> /dev/null; then echo "Error: curl not found." >&2; return 1; fi
    if ! command -v jq &> /dev/null; then echo "Error: jq not found." >&2; return 1; fi
    if ! command -v import &> /dev/null; then echo "Warning: 'import' command (ImageMagick) not found. Screenshots disabled." >&2; fi

    # --- API URLs and Auth ---
    local base_url="${EDC_API_URL%/}"
    local target_api_url="${base_url}/collector/api/targets/"
    local oplog_api_url="${base_url}/collector/api/oplog/" # Correct endpoint path
    local auth_header="Authorization: Token ${EDC_API_TOKEN}"

    echo "Fetching targets from API..."
    # --- Fetch All Targets ---
    local all_targets_json="[]"
    local next_url="${target_api_url}"
    local http_code response_body target_count target_ids target_hostnames target_ips
    # ... (Target fetching loop - keep the robust version from Response #50) ...
     while [[ -n "$next_url" && "$next_url" != "null" ]]; do
        http_code=$(curl -s -L -o /dev/null -w '%{http_code}' -H "${auth_header}" -H 'Accept: application/json' "${next_url}")
        local curl_exit_status=$?
        if [[ "$curl_exit_status" -ne 0 ]]; then echo "Error: curl command failed fetching targets (exit status ${curl_exit_status})." >&2; return 1; fi
        if [[ "$http_code" -ne 200 ]]; then
            response_body=$(curl -s -L -H "${auth_header}" -H 'Accept: application/json' "${next_url}")
            echo "Error: Failed to fetch targets page (HTTP ${http_code})" >&2; echo "$response_body" | jq '.' 2>/dev/null || echo "$response_body" >&2; return 1;
        fi
        response_body=$(curl -s -L -H "${auth_header}" -H 'Accept: application/json' "${next_url}")
        local results; results=$(echo "$response_body" | jq -c '.results'); if [[ -z "$results" || "$results" == "null" ]]; then echo "Error: No '.results' in target API response." >&2; echo "$response_body" | jq '.' >&2; return 1; fi
        all_targets_json=$(echo "$all_targets_json $results" | jq -c -s 'add')
        next_url=$(echo "$response_body" | jq -r '.next')
    done

    target_count=$(echo "$all_targets_json" | jq 'length')
    if [[ "$target_count" -eq 0 ]]; then echo "No targets found."; else
        mapfile -t target_ids < <(echo "$all_targets_json" | jq -r '.[].id')
        mapfile -t target_hostnames < <(echo "$all_targets_json" | jq -r '.[].hostname // "N/A"')
        mapfile -t target_ips < <(echo "$all_targets_json" | jq -r '.[].ip_address // "N/A"')
        echo "Found ${target_count} targets."
    fi

    # --- Prompt for Target Selection ---
    echo "Select Target:"
    echo "  [0] No Target"
    for i in "${!target_ids[@]}"; do printf "  [%d] %s (%s)\n" "$((i+1))" "${target_hostnames[i]}" "${target_ips[i]}"; done
    local target_choice selected_target_id=""
    while true; do
        read -p "Enter target number [0-${target_count}]: " target_choice
        if [[ "$target_choice" =~ ^[0-9]+$ ]] && [[ "$target_choice" -ge 0 ]] && [[ "$target_choice" -le "$target_count" ]]; then
            if [[ "$target_choice" -ne 0 ]]; then selected_target_id="${target_ids[$((target_choice-1))]}"; fi
            break
        else echo "Invalid choice." >&2; fi
    done

    # --- Get Command via Argument ---
    # (Using simple argument processing, requires calling like: log2 -c 'command here')
    local cmda=""
    local OPTIND # Reset OPTIND for getopts if function is called multiple times in one shell
    OPTIND=1
    while getopts ":c:d:" option; do # Added colon for silent errors from getopts
        case $option in
            c) cmda=$OPTARG;;
            d) desc=$OPTARG;;
            \?) echo "Invalid option: -$OPTARG" >&2; return 1;; # Handle invalid options
            :) echo "Option -$OPTARG requires an argument." >&2; return 1;; # Handle missing arguments
        esac
    done
    shift $((OPTIND -1)) # Remove processed options

    if [[ -z "$cmda" ]]; then
        echo "Usage: log -d nmap -c 'your command here'" >&2
        return 1
    fi

    # --- Execute Command, Capture Output, Take Screenshot ---
    local oput file now screenshot_opts
    echo "Executing command: $cmda"
    echo """


    """
    # Use script for safer execution and capture
    oput=$($cmda 2>&1 | tee /dev/tty)
    echo """


    """
    echo "Command finished. Output captured."

    now=$(TZ=UTC date +%Y%m%d_%H%M%S) # Use UTC for consistency
    file="/tmp/${now}_${operator}_${desc}.png" # Save screenshot to /tmp

    # Take screenshot only if 'import' command exists
    if command -v import &> /dev/null; then
        echo "Taking screenshot (wait 2s)..."
        sleep 1
        import -window root "$file" # Capture entire screen, adjust if needed
        if [[ $? -eq 0 ]]; then
             screenshot_opts=(-F "screenshot=@$file")
        else
             echo "Warning: Screenshot command failed." >&2
             screenshot_opts=()
             file="" # Clear filename if screenshot failed
        fi
        sleep 1
    else
        screenshot_opts=()
        file="" # No screenshot if command missing
    fi

    # --- Build and Execute curl POST Command ---
    echo "--- Submitting Oplog Entry ---"
    local curl_opts=()
    # Status code capture options
    curl_opts+=(-s -L -o /dev/null -w '%{http_code}')
    curl_opts+=(-X POST)
    curl_opts+=(-H "${auth_header}") # Token Auth Header

    # Add form fields using -F "key=value"
    curl_opts+=(-F "command=$cmda") # Correct field name
    curl_opts+=(-F "output=$oput")
    curl_opts+=(-F "src_host=$shost")
    curl_opts+=(-F "src_ip=$sip")
    curl_opts+=(-F "tool=$tool")
    # Add target_id only if selected
    if [[ -n "$selected_target_id" ]]; then
        curl_opts+=(-F "target_id=$selected_target_id")
    fi
    # Add screenshot if taken successfully
    if [[ -n "$file" && -f "$file" ]]; then
         curl_opts+=(-F "screenshot=@$file")
    fi
    # Add other fields like notes, url if needed via more args or prompts

    # Execute curl for status code
    local post_http_code
    post_http_code=$(curl "${curl_opts[@]}" "${oplog_api_url}") # Use correct endpoint URL
    local post_curl_exit_status=$?

    # --- Handle Response ---
    local post_response_body=""
    # Get body if needed
    if [[ "$post_curl_exit_status" -ne 0 ]]; then
         echo "Error: curl command failed submitting oplog (exit status ${post_curl_exit_status}). Could not connect?" >&2
         # Optionally try getting body/error message even on curl failure
          body_curl_opts=("${curl_opts[@]/-s /}") # Attempt without silent
          body_curl_opts=("${body_curl_opts[@]/-o \/dev\/null /}")
          body_curl_opts=("${body_curl_opts[@]/-w '%{http_code}'/}")
          post_response_body=$(curl "${body_curl_opts[@]}" "${oplog_api_url}" 2>&1)
          echo "Curl execution error output (if any): $post_response_body" >&2
         return 1 # Indicate failure
    elif [[ "$post_http_code" -eq 201 ]]; then # 201 Created
         body_curl_opts=("${curl_opts[@]/-s /}")
         body_curl_opts=("${body_curl_opts[@]/-o \/dev\/null /}")
         body_curl_opts=("${body_curl_opts[@]/-w '%{http_code}'/}")
         post_response_body=$(curl "${body_curl_opts[@]}" "${oplog_api_url}")
         echo "Oplog entry created"
    else # Handle non-201 server responses (like 400, 403, 500)
         body_curl_opts=("${curl_opts[@]/-s /}")
         body_curl_opts=("${body_curl_opts[@]/-o \/dev\/null /}")
         body_curl_opts=("${body_curl_opts[@]/-w '%{http_code}'/}")
         post_response_body=$(curl "${body_curl_opts[@]}" "${oplog_api_url}")
         echo "Error: Failed to create oplog entry (HTTP ${post_http_code})." >&2
         echo "Response Body:" >&2
         echo "$post_response_body" | jq '.' 2>/dev/null || echo "$post_response_body" >&2
         return 1 # Indicate failure
    fi

    # Optional: Clean up temporary screenshot
    if [[ -n "$file" && -f "$file" ]]; then
        rm "$file"
    fi

    return 0
}

_edc_api_request() {
    local method="$1"
    local url="$2"
    local json_data="$3" # Optional: for POST/PUT/PATCH
    local http_code
    local response_body
    local curl_opts=()
    local combined_output

    # Common options - run only ONCE
    curl_opts+=(-s -L) # Silent, follow redirects
    curl_opts+=(-X "$method")
    curl_opts+=(-H "Authorization: Token ${EDC_API_TOKEN}")
    curl_opts+=(-H "Accept: application/json")

    # Add data and content type for relevant methods
    if [[ "$method" == "POST" || "$method" == "PUT" || "$method" == "PATCH" ]]; then
        if [[ -z "$json_data" ]]; then
            echo "Error (_edc_api_request): JSON data required for $method." >&2
            return 1
        fi
        curl_opts+=(-H "Content-Type: application/json")
        curl_opts+=(-d "$json_data")
    fi

    # Add option to write status code AFTER the body, separated by a newline
    # This allows capturing both in one call
    curl_opts+=(-w '\n%{http_code}')

    # Execute curl and capture all output (body + status code line)
    combined_output=$(curl "${curl_opts[@]}" "${url}")
    local curl_exit_status=$?

    # --- Process output ---
    # Check curl exit status first
    if [[ "$curl_exit_status" -ne 0 ]]; then
        echo "Error: curl command failed (URL: ${url}, Exit Status: ${curl_exit_status}). Could not connect?" >&2
        # Output whatever curl printed (likely an error message)
        echo "$combined_output" >&2
        return 1
    fi

    # Separate the body from the status code (last line)
    # Check if output contains at least one newline
    if [[ "$combined_output" == *$'\n'* ]]; then
        http_code="${combined_output##*$'\n'}" # Extract last line
        response_body="${combined_output%$'\n'*}" # Extract lines before the last
    else
        # Handle case where output might only be the status code (e.g., HEAD or error with no body)
        http_code="$combined_output"
        response_body=""
    fi

    # Validate http_code looks like a number
    if ! [[ "$http_code" =~ ^[0-9]+$ ]]; then
         echo "Error: Failed to parse HTTP status code from curl output." >&2
         echo "Full curl output:" >&2
         echo "$combined_output" >&2
         return 1
    fi

    # --- Handle Response based on HTTP Code ---
    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
        # Output body to stdout for successful requests (unless HEAD)
        if [[ "$method" != "HEAD" ]]; then
             echo "$response_body"
        fi
        # Output status to stderr for logging/info
        echo "Request Succeeded (HTTP ${http_code})" >&2
        return 0 # Success
    else
        # Output status and body to stderr for failed requests
        echo "Error: API request failed (HTTP ${http_code})" >&2
        echo "Response Body:" >&2
        # Try to pretty print if JSON, otherwise print raw
        echo "$response_body" | jq '.' 2>/dev/null || echo "$response_body" >&2
        return 1 # Failure
    fi
}


function cred {
    local username="" password="" service="" notes=""
    local OPTIND OPTARG # Reset OPTIND for getopts
    OPTIND=1

    while getopts ":u:p:s:n:h" option; do
        case $option in
            u) username=$OPTARG;;
            p) password=$OPTARG;;
            s) service=$OPTARG;;
            n) notes=$OPTARG;;
            h) cred_usage; return 0;;
            \?) echo "Invalid option: -$OPTARG" >&2; cred_usage; return 1;;
            :) echo "Option -$OPTARG requires an argument." >&2; cred_usage; return 1;;
        esac
    done
    shift $((OPTIND -1))

    # Check required arguments
    if [[ -z "$username" ]] || [[ -z "$password" ]]; then
        echo "Error: Username (-u) and Password (-p) are required." >&2
        cred_usage
        return 1
    fi

    # Config Checks
    if [[ -z "$EDC_API_URL" ]]; then echo "Error: EDC_API_URL not set." >&2; return 1; fi
    if [[ -z "$EDC_API_TOKEN" ]]; then echo "Error: EDC_API_TOKEN not set." >&2; return 1; fi

    # Construct JSON Payload using jq
    local json_payload
    json_payload=$(jq -n \
        --arg user "$username" \
        --arg pass "$password" \
        --arg svc "$service" \
        --arg note "$notes" \
        '{username: $user, password_plaintext: $pass, service: $svc, notes: $note}')
        # Note: target_id, hash_value, hash_type are omitted, will be null/default

    local base_url="${EDC_API_URL%/}"
    local cred_api_url="${base_url}/collector/api/credentials/"

    echo "Submitting credential for user '${username}'..."

    # Use helper function for the API request
    local api_response
    if api_response=$(_edc_api_request POST "$cred_api_url" "$json_payload"); then
        # Success output already printed by helper to stderr, print body nicely
        echo "Credential created successfully. Response:"
        echo "$api_response" | jq '.'
        return 0
    else
        # Error already printed by helper to stderr
        return 1
    fi
}

cred_usage() {
    echo "Usage: cred -u <username> -p <password> [-s <service>] [-n <notes>] [-h]"
    echo "  Adds a credential entry via the EDC API."
    echo "  Arguments:"
    echo "    -u USERNAME : Username for the credential (required)."
    echo "    -p 'PASSWORD' : Password/secret for the credential (required). Quote if contains spaces/special chars."
    echo "    -s SERVICE  : Service the credential is for (optional, e.g., SSH, SMB, HTTP)."
    echo "    -n NOTES    : Notes about the credential (optional). Quote if contains spaces."
    echo "    -h          : Display this help message."
    echo "  Requires EDC_API_URL and EDC_API_TOKEN environment variables."
}

function target {
    local ip="" host="" os="" desc=""
    local OPTIND OPTARG # Reset OPTIND for getopts
    OPTIND=1

    while getopts ":i:h:o:d:" option; do
        case $option in
            i) ip=$OPTARG;;
            h) host=$OPTARG;;
            o) os=$OPTARG;;
            d) desc=$OPTARG;;
            \?) echo "Invalid option: -$OPTARG" >&2; target_usage; return 1;;
            :) echo "Option -$OPTARG requires an argument." >&2; target_usage; return 1;;
         esac
    done
    shift $((OPTIND -1))

    # Check required arguments
    if [[ -z "$ip" && -z "$host" ]]; then
        echo "Error: At least one of IP Address (-i) or Hostname (-h) must be provided." >&2
        target_usage
        return 1
    fi

     # Config Checks
    if [[ -z "$EDC_API_URL" ]]; then echo "Error: EDC_API_URL not set." >&2; return 1; fi
    if [[ -z "$EDC_API_TOKEN" ]]; then echo "Error: EDC_API_TOKEN not set." >&2; return 1; fi

    # Construct JSON Payload conditionally using jq
    local json_payload
    json_payload=$(jq -n \
        --arg ipaddr "$ip" \
        --arg hname "$host" \
        --arg osys "$os" \
        --arg dsc "$desc" \
        '{} |
         if $ipaddr != "" then .ip_address = $ipaddr else . end |
         if $hname != "" then .hostname = $hname else . end |
         if $osys != "" then .operating_system = $osys else . end |
         if $dsc != "" then .description = $dsc else . end
        ')

    local base_url="${EDC_API_URL%/}"
    local target_api_url="${base_url}/collector/api/targets/"

    echo "Submitting target..."
    echo "Payload: $json_payload"

    # Use helper function for the API request
    local api_response
    if api_response=$(_edc_api_request POST "$target_api_url" "$json_payload"); then
        echo "Target created successfully. Response:"
        echo "$api_response" | jq '.'
        return 0
    else
        return 1
    fi
}

target_usage() {
    echo "Usage: target [-i <ip_address>] [-h <hostname>] [-o <os>] [-d <description>]"
    echo "  Adds a target entry via the EDC API."
    echo "  Arguments:"
    echo "    -i IP_ADDRESS   : IP address of the target (optional, but required if -h is omitted)."
    echo "    -h HOSTNAME     : Hostname of the target (optional, but required if -i is omitted)."
    echo "    -o OS           : Operating System (optional)."
    echo "    -d DESCRIPTION  : Description (optional). Quote if contains spaces."
    echo "  Requires EDC_API_URL and EDC_API_TOKEN environment variables."
}