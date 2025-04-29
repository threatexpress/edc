EDC_API_URL=http://127.0.0.1:8000/
EDC_API_TOKEN="tokenhere"
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
    curl_opts+=(-w '\n%{http_code}')

    # Execute curl and capture all output (body + status code line)
    combined_output=$(curl "${curl_opts[@]}" "${url}")
    local curl_exit_status=$?

    # --- Process output ---
    if [[ "$curl_exit_status" -ne 0 ]]; then
        echo "Error: curl command failed (URL: ${url}, Exit Status: ${curl_exit_status}). Could not connect?" >&2
        echo "$combined_output" >&2
        return 1
    fi
    if [[ "$combined_output" == *$'\n'* ]]; then
        http_code="${combined_output##*$'\n'}"; response_body="${combined_output%$'\n'*}"; else
        http_code="$combined_output"; response_body=""; fi
    if ! [[ "$http_code" =~ ^[0-9]+$ ]]; then
        echo "Error: Failed to parse HTTP status code from curl output." >&2; echo "Full curl output:" >&2; echo "$combined_output" >&2; return 1; fi

    # --- Handle Response based on HTTP Code ---
    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
        if [[ "$method" != "HEAD" ]]; then echo "$response_body"; fi # Output body on success
        echo "Request Succeeded (HTTP ${http_code})" >&2
        return 0 # Success
    else
        echo "Error: API request failed (HTTP ${http_code})" >&2; echo "Response Body:" >&2
        echo "$response_body" | jq '.' 2>/dev/null || echo "$response_body" >&2 # Output body on error
        return 1 # Failure
    fi
}


# ==============================================================================
# Function to add or list Credentials (v2 - Added -l)
# Usage: cred -l | cred -u <username> -p <password> [-s <service>] [-n <notes>] [-h]
# ==============================================================================
function cred {
    local username="" password="" service="" notes="" list_mode=false
    local OPTIND OPTARG # Reset OPTIND for getopts
    OPTIND=1

    # Add 'l' to getopts string
    while getopts ":lu:p:s:n:h" option; do
        case $option in
            l) list_mode=true;; # Set list mode flag
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

    # --- Config Checks --- (Needed for both list and add)
    if [[ -z "$EDC_API_URL" ]]; then echo "Error: EDC_API_URL not set." >&2; return 1; fi
    if [[ -z "$EDC_API_TOKEN" ]]; then echo "Error: EDC_API_TOKEN not set." >&2; return 1; fi
    if ! command -v jq &> /dev/null; then echo "Error: jq not found." >&2; return 1; fi


    local base_url="${EDC_API_URL%/}"
    local cred_api_url="${base_url}/collector/api/credentials/"

    # --- List Mode ---
    if [[ "$list_mode" == true ]]; then
        echo "Listing credentials (first page)..."
        local api_response
        # Use helper for GET request
        if api_response=$(_edc_api_request GET "$cred_api_url"); then
            # Pretty print the JSON response using jq
            echo "$api_response" | jq '.results[] | {username, password_plaintext}'
            # Note: This only shows the first page if pagination is enabled.
            # You could enhance this to fetch all pages using the '.next' field.
            return 0
        else
            # Error already printed by helper
            return 1
        fi
    fi

    # Check required arguments for add mode
    if [[ -z "$username" ]] || [[ -z "$password" ]]; then
        echo "Error: Username (-u) and Password (-p) are required for adding." >&2
        cred_usage
        return 1
    fi

    # Construct JSON Payload
    local json_payload
    json_payload=$(jq -n --arg u "$username" --arg p "$password" --arg s "$service" --arg n "$notes" \
        '{username: $u, password_plaintext: $p, service: $s, notes: $n}')

    echo "Submitting credential for user '${username}'..."
    local api_response_add # Use different variable name
    if api_response_add=$(_edc_api_request POST "$cred_api_url" "$json_payload"); then
        echo "Credential created successfully. Response:"
        echo "$api_response_add" | jq '.'
        return 0
    else
        return 1
    fi
}

cred_usage() {
    echo "Usage: cred -l | cred -u <username> -p <password> [-s <service>] [-n <notes>] [-h]"
    echo "  Adds or lists credentials via the EDC API."
    echo "  Options:"
    echo "    -l          : List existing credentials (shows first page)."
    echo "    -u USERNAME : Username for adding a credential (required for add)."
    echo "    -p 'PASSWORD' : Password/secret (required for add). Quote if needed."
    echo "    -s SERVICE  : Service the credential is for (optional)."
    echo "    -n NOTES    : Notes about the credential (optional). Quote if needed."
    echo "    -h          : Display this help message."
    echo "  Requires EDC_API_URL and EDC_API_TOKEN environment variables."
}


# ==============================================================================
# Function to add or list Targets (v2 - Added -l)
# Usage: target -l | target [-i <ip>] [-h <host>] [-o <os>] [-d <desc>]
# ==============================================================================
function target {
    local ip="" host="" os="" desc="" list_mode=false
    local OPTIND OPTARG
    OPTIND=1

    # Add 'l' to getopts string
    while getopts ":li:h:o:d:" option; do
        case $option in
            l) list_mode=true;;
            i) ip=$OPTARG;;
            h) host=$OPTARG;;
            o) os=$OPTARG;;
            d) desc=$OPTARG;;
            \?) echo "Invalid option: -$OPTARG" >&2; target_usage; return 1;;
            :) echo "Option -$OPTARG requires an argument." >&2; target_usage; return 1;;
         esac
    done
    shift $((OPTIND -1))

    # --- Config Checks ---
    if [[ -z "$EDC_API_URL" ]]; then echo "Error: EDC_API_URL not set." >&2; return 1; fi
    if [[ -z "$EDC_API_TOKEN" ]]; then echo "Error: EDC_API_TOKEN not set." >&2; return 1; fi
    if ! command -v jq &> /dev/null; then echo "Error: jq not found." >&2; return 1; fi


    local base_url="${EDC_API_URL%/}"
    local target_api_url="${base_url}/collector/api/targets/"

    # --- List Mode ---
    if [[ "$list_mode" == true ]]; then
        echo "Listing targets (first page)..."
        local api_response
        if api_response=$(_edc_api_request GET "$target_api_url"); then
            # Pretty print JSON using jq
            echo "$api_response" | jq '.results[] | {ip_address, hostname}'
            return 0
        else
            return 1
        fi
    fi

    # --- Add Mode (Original Logic) ---
    # Check required arguments for add mode
    if [[ -z "$ip" && -z "$host" ]]; then
        echo "Error: At least IP Address (-i) or Hostname (-h) required for adding." >&2
        target_usage
        return 1
    fi

    # Construct JSON Payload
    local json_payload
    json_payload=$(jq -n --arg ipa "$ip" --arg hn "$host" --arg osys "$os" --arg dsc "$desc" \
        '{} |
         if $ipa != "" then .ip_address = $ipa else . end |
         if $hn != "" then .hostname = $hn else . end |
         if $osys != "" then .operating_system = $osys else . end |
         if $dsc != "" then .description = $dsc else . end')

    echo "Submitting target..."
    echo "Payload: $json_payload"
    local api_response_add
    if api_response_add=$(_edc_api_request POST "$target_api_url" "$json_payload"); then
        echo "Target created successfully. Response:"
        echo "$api_response_add" | jq '.'
        return 0
    else
        return 1
    fi
}

target_usage() {
    echo "Usage: target -l | target [-i <ip>] [-h <host>] [-o <os>] [-d <desc>]"
    echo "  Adds or lists targets via the EDC API."
    echo "  Options:"
    echo "    -l          : List existing targets (shows first page)."
    echo "    -i IP_ADDRESS : IP address for adding a target (required if -h omitted)."
    echo "    -h HOSTNAME   : Hostname for adding a target (required if -i omitted)."
    echo "    -o OS         : Operating System (optional)."
    echo "    -d DESCRIPTION: Description (optional). Quote if needed."
    echo "  Requires EDC_API_URL and EDC_API_TOKEN environment variables."
}


# ==============================================================================
# Function to add or list Oplog Entries (v6 - Added -l)
# Usage: log -l | log -c 'command' [-d 'description']
#        Note: Add mode still fetches/prompts for target interactively.
# ==============================================================================
function log {
    local list_mode=false
    local cmda="" desc="" # For create mode
    local OPTIND=1

    # Add 'l' to getopts string
    while getopts ":lc:d:" option; do
        case $option in
            l) list_mode=true;;
            c) cmda=$OPTARG;;
            d) desc=$OPTARG;;
            \?) echo "Invalid option: -$OPTARG" >&2; log_help; return 1;;
            :) echo "Option -$OPTARG requires an argument." >&2; log_help; return 1;;
        esac
    done
    # Don't shift yet if list_mode is false, allow no args for list mode either? No, require -l
    # Check if only -l was passed or no args (assuming list) - simpler check:
    if [[ "$1" == "-l" ]]; then
        list_mode=true
    fi

    # --- Config Checks ---
    if [[ -z "$EDC_API_URL" ]]; then echo "Error: EDC_API_URL not set." >&2; return 1; fi
    if [[ -z "$EDC_API_TOKEN" ]]; then echo "Error: EDC_API_TOKEN not set." >&2; return 1; fi
    if ! command -v jq &> /dev/null; then echo "Error: jq not found." >&2; return 1; fi


    local base_url="${EDC_API_URL%/}"
    local oplog_api_url="${base_url}/collector/api/oplog/"
    local target_api_url="${base_url}/collector/api/targets/" # Still needed for add mode
    local auth_header="Authorization: Token ${EDC_API_TOKEN}"

    # --- List Mode ---
    if [[ "$list_mode" == true ]]; then
        echo "Listing Oplog entries (first page)..."
        local api_response
        if api_response=$(_edc_api_request GET "$oplog_api_url"); then
            # Pretty print JSON using jq
            echo "$api_response" | jq '.results[] | {id, target, command}'
             # Suggest filtering with jq:
            echo ""
            return 0
        else
            return 1
        fi
    fi

    # Reset OPTIND and re-parse for create arguments (-c is required)
    OPTIND=1
    cmda="" # Reset cmda
    while getopts ":c:d:" option; do
        case $option in
            c) cmda=$OPTARG;;
            d) desc=$OPTARG;; # Map -d to notes
        esac
    done
    shift $((OPTIND -1)) # Remove processed options

    if [[ -z "$cmda" ]]; then
        echo "Error: Command (-c) is required for adding an Oplog entry." >&2
        log_help
        return 1
    fi

    # Assume 'operator' env var and 'my_ip' function exist/checked
    if [[ -z "$operator" ]]; then echo "Warning: 'operator' not set, using 'unknown'." >&2; operator="unknown"; fi
    local sip; if command -v my_ip &> /dev/null; then sip=$(my_ip); else echo "Warning: my_ip not found." >&2; sip="127.0.0.1"; fi
    local shost; shost=$(hostname); local tool="terminal"
    if ! command -v import &> /dev/null; then echo "Warning: 'import' command disabled." >&2; fi
    if ! command -v tee &> /dev/null; then echo "Error: 'tee' command not found." >&2; return 1; fi


    # --- Fetch Targets for Selection ---
    echo "Fetching targets from API..."
    local all_targets_json="[]" next_url="${target_api_url}" http_code response_body
    local target_count target_ids target_hostnames target_ips
    # ... (Target fetching loop - keep the robust version) ...
     while [[ -n "$next_url" && "$next_url" != "null" ]]; do
        http_code=$(curl -s -L -o /dev/null -w '%{http_code}' -H "${auth_header}" -H 'Accept: application/json' "${next_url}")
        local curl_exit_status=$?; if [[ "$curl_exit_status" -ne 0 ]]; then echo "Error: curl failed fetching targets (exit ${curl_exit_status})." >&2; return 1; fi
        if [[ "$http_code" -ne 200 ]]; then response_body=$(curl -s -L -H "${auth_header}" -H 'Accept: application/json' "${next_url}"); echo "Error: Failed targets fetch (HTTP ${http_code})" >&2; echo "$response_body"|jq '.' 2>/dev/null||echo "$response_body" >&2; return 1; fi
        response_body=$(curl -s -L -H "${auth_header}" -H 'Accept: application/json' "${next_url}")
        local results; results=$(echo "$response_body" | jq -c '.results'); if [[ -z "$results" || "$results" == "null" ]]; then echo "Error: No '.results' in target API response." >&2; echo "$response_body"|jq '.' >&2; return 1; fi
        all_targets_json=$(echo "$all_targets_json $results" | jq -c -s 'add')
        next_url=$(echo "$response_body" | jq -r '.next')
    done
    target_count=$(echo "$all_targets_json" | jq 'length')
    if [[ "$target_count" -eq 0 ]]; then echo "No targets found."; else
        mapfile -t target_ids < <(echo "$all_targets_json" | jq -r '.[].id'); mapfile -t target_hostnames < <(echo "$all_targets_json" | jq -r '.[].hostname // "N/A"'); mapfile -t target_ips < <(echo "$all_targets_json" | jq -r '.[].ip_address // "N/A"'); echo "Found ${target_count} targets."
    fi

    # --- Prompt for Target Selection ---
    echo "Select Target:"; echo "  [0] No Target"; for i in "${!target_ids[@]}"; do printf "  [%d] %s (%s)\n" "$((i+1))" "${target_hostnames[i]}" "${target_ips[i]}"; done
    local target_choice selected_target_id=""; while true; do read -p "Enter target number [0-${target_count}]: " target_choice; if [[ "$target_choice" =~ ^[0-9]+$ && "$target_choice" -ge 0 && "$target_choice" -le "$target_count" ]]; then if [[ "$target_choice" -ne 0 ]]; then selected_target_id="${target_ids[$((target_choice-1))]}"; fi; break; else echo "Invalid choice." >&2; fi; done

    # --- Execute Command, Capture Output, Take Screenshot ---
    local oput file now screenshot_opts
    echo """


    """
    echo "--- Executing Command ---"; 
    echo ">>> ${cmda}"; echo "--- Output ---"
    oput=$($cmda 2>&1 | tee /dev/tty)
    echo "--- Command Finished ---"
    echo $cmda
    echo """


    """


    now=$(TZ=UTC date +%Y%m%d_%H%M%S); file="/tmp/${now}_${operator}_${desc}.png"
    screenshot_opts=(); if command -v import &> /dev/null; then echo "Taking screenshot (wait 1s)..."; sleep 1; import -window root "$file"; if [[ $? -eq 0 ]]; then echo ""; else echo "Warning: Screenshot failed." >&2; file=""; fi; else file=""; fi

    # --- Build and Execute curl POST Command (SINGLE CALL) ---
    echo "--- Submitting Oplog Entry ---"
    local curl_opts=(); local combined_output; local post_http_code; local post_response_body;
    curl_opts+=(-s -L); curl_opts+=(-X POST); curl_opts+=(-H "${auth_header}")
    curl_opts+=(-F "command=$cmda"); curl_opts+=(-F "output=$oput"); curl_opts+=(-F "src_host=$shost"); curl_opts+=(-F "src_ip=$sip"); curl_opts+=(-F "tool=$tool")
    # Use 'notes' field for description passed via -d
    if [[ -n "$selected_target_id" ]]; then curl_opts+=(-F "target_id=$selected_target_id"); fi
    if [[ -n "$file" && -f "$file" ]]; then curl_opts+=(-F "screenshot=@$file"); fi
    curl_opts+=(-w '\n%{http_code}') # Status code last

    combined_output=$(curl "${curl_opts[@]}" "${oplog_api_url}")
    local post_curl_exit_status=$?

    # --- Process combined output ---
    if [[ "$post_curl_exit_status" -ne 0 ]]; then echo "Error: curl failed submitting oplog (exit status ${post_curl_exit_status})." >&2; echo "Curl output: $combined_output" >&2; if [[ -n "$file" && -f "$file" ]]; then rm "$file"; fi; return 1; fi
    if [[ "$combined_output" == *$'\n'* ]]; then post_http_code="${combined_output##*$'\n'}"; post_response_body="${combined_output%$'\n'*}"; else post_http_code="$combined_output"; post_response_body=""; fi
    if ! [[ "$post_http_code" =~ ^[0-9]+$ ]]; then echo "Error: Failed to parse HTTP status code." >&2; echo "Full Output: $combined_output" >&2; if [[ -n "$file" && -f "$file" ]]; then rm "$file"; fi; return 1; fi

    # --- Handle Response ---
    if [[ "$post_http_code" -eq 201 ]]; then echo ""; else echo "Error: Failed to create oplog entry (HTTP ${post_http_code})." >&2; echo "Response Body:" >&2; echo "$post_response_body" | jq '.' 2>/dev/null || echo "$post_response_body" >&2; if [[ -n "$file" && -f "$file" ]]; then rm "$file"; fi; return 1; fi

    if [[ -n "$file" && -f "$file" ]]; then rm "$file"; fi
    return 0
}

# Helper function for log usage
log_help() {
    echo "Usage: log -l | log -d 'description' -c 'command to execute' "
    echo "  Adds or lists Oplog entries via the EDC API."
    echo "  Options:"
    echo "    -l          : List existing Oplog entries (shows first page)."
    echo "    -c COMMAND  : Command that was executed (required for add)."
    echo "    -d DESCRIPTION : Simple screenshot description for the log entry."
    echo "  Requires EDC_API_URL and EDC_API_TOKEN environment variables."
}