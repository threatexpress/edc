# ~/.zshrc for zsh interactive shells.
# Last Updated: 2025-06-28

# ==============================================================================
#                   EDC (Engagement Data Collector) Configuration
#                   Change only TOKEN and operator
# ==============================================================================

# IMPORTANT: Ensure 'operator' & 'EDC_API_TOKEN' are unique for each distinct user.
export EDC_API_URL="http://10.62.0.2:8889"
#export EDC_API_TOKEN="3dd9db6cce9c3c8f4802e94c4f5adc3e1d2b8104" #kali1
export EDC_API_TOKEN="3dd9db6cce9c3c8f4802e94c4f5adc3e1d2b8104" #kali2
#export EDC_API_TOKEN="3dd9db6cce9c3c8f4802e94c4f5adc3e1d2b8104" #kali3
#export EDC_API_TOKEN="3dd9db6cce9c3c8f4802e94c4f5adc3e1d2b8104" #kali4
#export EDC_API_TOKEN="3dd9db6cce9c3c8f4802e94c4f5adc3e1d2b8104" #kali5
export operator=${operator:-"kali2"} # Each user should customize this to match the token.


# ==============================================================================
#                        Dynamic Log Storage
# ==============================================================================

# IMPORTANT: Define the path to YOUR network share mount point.
SHARE_MOUNT_TARGET="${HOME}/Desktop/vise-share" # Verify this path!
LOG_SUBDIR_BASENAME="5-logs"
if mountpoint -q "${SHARE_MOUNT_TARGET}" 2>/dev/null; then
    export ZSH_LOG_DIRECTORY="${SHARE_MOUNT_TARGET}/${LOG_SUBDIR_BASENAME}"
else
    export ZSH_LOG_DIRECTORY="${HOME}/Desktop/${LOG_SUBDIR_BASENAME}"
fi

# Ensure the base log directory and its essential subdirectories exist.
mkdir -p "${ZSH_LOG_DIRECTORY}/screenshots"
mkdir -p "${ZSH_LOG_DIRECTORY}/pcaps"
mkdir -p "${ZSH_LOG_DIRECTORY}/terminals"


# ==============================================================================
#                         Standard Zsh Configuration
#                               Section 1
# ==============================================================================
HOSTNAME_SHORT=$(hostname -s)

: ${DISPLAY:=:0}
export DISPLAY

# Activates the Python virtual environment for this shell session.
source ~/venv/bin/activate

# ==============================================================================
#                           Prompt Config and Options
#                         Standard zsh config section 2
# ==============================================================================
# Options
setopt APPEND_HISTORY
setopt autocd
setopt interactivecomments
setopt magicequalsubst
setopt nonomatch
setopt notify
setopt numericglobsort
setopt promptsubst
WORDCHARS=${WORDCHARS//\/}
PROMPT_EOL_MARK=""

# configure key keybindings
bindkey -e
bindkey ' ' magic-space
bindkey '^U' backward-kill-line
bindkey '^[[3;5~' kill-word
bindkey '^[[3~' delete-char
bindkey '^[[1;5C' forward-word
bindkey '^[[1;5D' backward-word
bindkey '^[[5~' beginning-of-buffer-or-history
bindkey '^[[6~' end-of-buffer-or-history
bindkey '^[[H' beginning-of-line
bindkey '^[[F' end-of-line
bindkey '^[[Z' undo

# enable completion features
autoload -Uz compinit
compinit -d ~/.cache/zcompdump
zstyle ':completion:*:*:*:*:*' menu select
zstyle ':completion:*' auto-description 'specify: %d'
zstyle ':completion:*' completer _expand _complete
zstyle ':completion:*' format 'Completing %d'
zstyle ':completion:*' group-name ''
zstyle ':completion:*' list-colors ''
zstyle ':completion:*' list-prompt %SAt %p: Hit TAB for more, or the character to insert%s
zstyle ':completion:*' matcher-list 'm:{a-zA-Z}={A-Za-z}'
zstyle ':completion:*' rehash true
zstyle ':completion:*' select-prompt %SScrolling active: current selection at %p%s
zstyle ':completion:*' use-compctl false
zstyle ':completion:*' verbose true
zstyle ':completion:*:kill:*' command 'ps -u $USER -o pid,%cpu,tty,cputime,cmd'

# History configurations
HISTFILE=~/.zsh_history
HIST=ignoreboth
HISTSIZE=1000
SAVEHIST=2000
HISTFILESIZE=2000
HISTTIMEFORMAT='%Y%m%d_%H%M%S '
setopt hist_expire_dups_first
setopt hist_ignore_dups
setopt hist_ignore_space
setopt hist_verify
alias history="history 0"
TIMEFMT=$'\nreal\t%E\nuser\t%U\nsys\t%S\ncpu\t%P'


# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# fancy color prompt
case "$TERM" in xterm-color|*-256color) color_prompt=yes;; esac
force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
        color_prompt=yes
    else
        color_prompt=
    fi
fi

# prompt symbols
configure_prompt() {
    prompt_symbol=㉿
    case "$PROMPT_ALTERNATIVE" in
        twoline)
            PROMPT=$'%F{%(#.blue.green)}┌──${debian_chroot:+($debian_chroot)─}${VIRTUAL_ENV:+($(basename $VIRTUAL_ENV))─}(%B%F{%(#.red.blue)}%n'$prompt_symbol$'%m%b%F{%(#.blue.green)})-[%B%F{reset}%(6~.%-1~/…/%4~.%5~)%b%F{%(#.blue.green)}]\n└─%B%(#.%F{red}#.%F{blue}$)%b%F{reset} '
            ;;
        oneline)
            PROMPT=$'${debian_chroot:+($debian_chroot)}${VIRTUAL_ENV:+($(basename $VIRTUAL_ENV))}%B%F{%(#.red.blue)}%n@%m%b%F{reset}:%B%F{%(#.blue.green)}%~%b%F{reset}%(#.#.$) '
            RPROMPT=
            ;;
        backtrack)
            PROMPT=$'${debian_chroot:+($debian_chroot)}${VIRTUAL_ENV:+($(basename $VIRTUAL_ENV))}%B%F{red}%n@%m%b%F{reset}:%B%F{blue}%~%b%F{reset}%(#.#.$) '
            RPROMPT=
            ;;
    esac
    unset prompt_symbol
}

PROMPT_ALTERNATIVE=twoline
NEWLINE_BEFORE_PROMPT=yes

if [ "$color_prompt" = yes ]; then
    VIRTUAL_ENV_DISABLE_PROMPT=1
    configure_prompt

    if [ -f /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh ]; then
        . /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
        ZSH_HIGHLIGHT_HIGHLIGHTERS=(main brackets pattern)
        ZSH_HIGHLIGHT_STYLES[default]=none; ZSH_HIGHLIGHT_STYLES[unknown-token]=underline; ZSH_HIGHLIGHT_STYLES[reserved-word]=fg=cyan,bold; ZSH_HIGHLIGHT_STYLES[suffix-alias]=fg=green,underline; ZSH_HIGHLIGHT_STYLES[global-alias]=fg=green,bold; ZSH_HIGHLIGHT_STYLES[precommand]=fg=green,underline; ZSH_HIGHLIGHT_STYLES[commandseparator]=fg=blue,bold; ZSH_HIGHLIGHT_STYLES[autodirectory]=fg=green,underline; ZSH_HIGHLIGHT_STYLES[path]=bold; ZSH_HIGHLIGHT_STYLES[path_pathseparator]=; ZSH_HIGHLIGHT_STYLES[path_prefix_pathseparator]=; ZSH_HIGHLIGHT_STYLES[globbing]=fg=blue,bold; ZSH_HIGHLIGHT_STYLES[history-expansion]=fg=blue,bold; ZSH_HIGHLIGHT_STYLES[command-substitution]=none; ZSH_HIGHLIGHT_STYLES[command-substitution-delimiter]=fg=magenta,bold; ZSH_HIGHLIGHT_STYLES[process-substitution]=none; ZSH_HIGHLIGHT_STYLES[process-substitution-delimiter]=fg=magenta,bold; ZSH_HIGHLIGHT_STYLES[single-hyphen-option]=fg=green; ZSH_HIGHLIGHT_STYLES[double-hyphen-option]=fg=green; ZSH_HIGHLIGHT_STYLES[back-quoted-argument]=none; ZSH_HIGHLIGHT_STYLES[back-quoted-argument-delimiter]=fg=blue,bold; ZSH_HIGHLIGHT_STYLES[single-quoted-argument]=fg=yellow; ZSH_HIGHLIGHT_STYLES[double-quoted-argument]=fg=yellow; ZSH_HIGHLIGHT_STYLES[dollar-quoted-argument]=fg=yellow; ZSH_HIGHLIGHT_STYLES[rc-quote]=fg=magenta; ZSH_HIGHLIGHT_STYLES[dollar-double-quoted-argument]=fg=magenta,bold; ZSH_HIGHLIGHT_STYLES[back-double-quoted-argument]=fg=magenta,bold; ZSH_HIGHLIGHT_STYLES[back-dollar-quoted-argument]=fg=magenta,bold; ZSH_HIGHLIGHT_STYLES[assign]=none; ZSH_HIGHLIGHT_STYLES[redirection]=fg=blue,bold; ZSH_HIGHLIGHT_STYLES[comment]=fg=black,bold; ZSH_HIGHLIGHT_STYLES[named-fd]=none; ZSH_HIGHLIGHT_STYLES[numeric-fd]=none; ZSH_HIGHLIGHT_STYLES[arg0]=fg=cyan; ZSH_HIGHLIGHT_STYLES[bracket-error]=fg=red,bold; ZSH_HIGHLIGHT_STYLES[bracket-level-1]=fg=blue,bold; ZSH_HIGHLIGHT_STYLES[bracket-level-2]=fg=green,bold; ZSH_HIGHLIGHT_STYLES[bracket-level-3]=fg=magenta,bold; ZSH_HIGHLIGHT_STYLES[bracket-level-4]=fg=yellow,bold; ZSH_HIGHLIGHT_STYLES[bracket-level-5]=fg=cyan,bold; ZSH_HIGHLIGHT_STYLES[cursor-matchingbracket]=standout;
    fi
else
    PROMPT='${debian_chroot:+($debian_chroot)}%n@%m:%~%(#.#.$) '
fi
unset color_prompt force_color_prompt

toggle_oneline_prompt(){
    if [ "$PROMPT_ALTERNATIVE" = oneline ]; then
        PROMPT_ALTERNATIVE=twoline
    else
        PROMPT_ALTERNATIVE=oneline
    fi
    configure_prompt
    zle reset-prompt
}
zle -N toggle_oneline_prompt
bindkey ^P toggle_oneline_prompt

precmd() {
    print -Pnr -- "$TERM_TITLE"
    if [ "$NEWLINE_BEFORE_PROMPT" = yes ]; then if [ -z "$_NEW_LINE_BEFORE_PROMPT" ]; then _NEW_LINE_BEFORE_PROMPT=1; else print ""; fi; fi
}

if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    export LS_COLORS="$LS_COLORS:ow=30;44:" # fix ls color for folders with 777 permissions
    alias ls='ls --color=auto'
    alias dir='dir --color=auto'
    alias vdir='vdir --color=auto'
    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
    alias diff='diff --color=auto'
    alias ip='ip --color=auto'
    alias ll='ls -alF --color=auto'
    alias la='ls -AalhG --color=auto'
    alias lg='ls -AalhG --color=auto |grep $1'
    alias l='ls -CF --color=auto'
    alias el='sudo $(history -p \!\!)'
    alias level='echo $SHLVL'
    alias ext_ip='curl -s ifconfig.me'
    alias netstati='lsof -P -i -n'
    export LESS_TERMCAP_mb=$'\E[1;31m'; export LESS_TERMCAP_md=$'\E[1;36m'; export LESS_TERMCAP_me=$'\E[0m'; export LESS_TERMCAP_so=$'\E[01;33m'; export LESS_TERMCAP_se=$'\E[0m'; export LESS_TERMCAP_us=$'\E[1;32m'; export LESS_TERMCAP_ue=$'\E[0m';
    zstyle ':completion:*' list-colors "${(s.:.)LS_COLORS}"
    zstyle ':completion:*:*:kill:*:processes' list-colors '=(#b) #([0-9]#)*=0=01;31'
fi

# enable auto-suggestions based on the history
if [ -f /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh ]; then
    . /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh
    ZSH_AUTOSUGGEST_HIGHLIGHT_STYLE='fg=#999'
fi

# enable command-not-found if installed
if [ -f /etc/zsh_command_not_found ]; then
    . /etc/zsh_command_not_found
fi

PS1=$'\n%F{white}╭ [%F{reset}$(if [[ $? == 0 ]]; then echo "%F{green}✓%F{reset}"; else echo "%F{red}✕%F{reset}"; fi) %F{yellow}%D{%Y%m%d_%H%M%S_%zUC}%F{white} %n@%m %F{cyan}$(my_ip)%F{blue}: %F{white}]\n├ [%F{green}%~%F{white}]\n%F{white}╰ %# '


# ==============================================================================
#                                     Functions
#                             Standard zsh config section 3
# ==============================================================================

function my_ip() {
    ip -4 addr | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n 1
}

function search(){
    grep -R "$1" ~/logs/terminals/
}

function mkcd() {
    mkdir -p "$@" && cd "$_";
}

function sst() {
    if [[ $# -ne 2 ]]; then echo "Usage: sst <desc_no_spaces> <target_ip_or_host>"; return 1; fi
    local subject="$1"; local suffix="$2"
    local dt; dt=$(date '+%Y%m%d_%H%M%S')
    local filename="${ZSH_LOG_DIRECTORY}/screenshots/${dt}_${operator}_${HOSTNAME_SHORT}_${subject}_${suffix}.png"
    echo "Taking screenshot, select window or area..."; import "$filename"
    if [ $? -eq 0 ]; then echo "Screenshot saved: $filename"; else echo "Screenshot failed."; fi
}


# ==============================================================================
#                        Robust Logging Configuration
#                        Standard zsh config section 4
# ==============================================================================

# Define a local cache directory for script logs
LOCAL_SCRIPT_LOG_CACHE_DIR="${HOME}/.cache/zsh_script_logs_cache"
if [ ! -d "${LOCAL_SCRIPT_LOG_CACHE_DIR}" ]; then
    mkdir -p "${LOCAL_SCRIPT_LOG_CACHE_DIR}"
fi

# Global variable to store the path to the raw log file for the current script session
# Prefixing with underscore is a common convention for "private" or internal-use global variables.
_ZSH_SCRIPT_SESSION_RAW_LOG_PATH=""

# Function to be called on Zsh exit to process and move the script log
_zsh_script_log_cleanup() {
    # Ensure this trap only runs once if multiple exit signals are received somehow
    # and to prevent recursion if any command in the trap causes an exit.
    trap - EXIT # Clear the trap for itself

    if [ -n "$_ZSH_SCRIPT_SESSION_RAW_LOG_PATH" ] && [ -f "$_ZSH_SCRIPT_SESSION_RAW_LOG_PATH" ]; then
        # Add a small visual separator for trap output if terminal is still visible
        printf "\n--- Zsh Exit: Processing Terminal Log ---\n"

        # Derive cleaned and final paths based on the raw path
        local raw_log_path_for_trap="$_ZSH_SCRIPT_SESSION_RAW_LOG_PATH" # Copy to local var for clarity
        local base_raw_filename=$(basename "$raw_log_path_for_trap")
        local base_log_filename="${base_raw_filename%.log.raw}" # Removes .log.raw extension
        
        local cleaned_local_log_path_for_trap="${LOCAL_SCRIPT_LOG_CACHE_DIR}/${base_log_filename}.log"
        local final_target_log_path_for_trap="${ZSH_LOG_DIRECTORY}/terminals/${base_log_filename}.log"

        printf "EXIT_TRAP: Processing: %s\n" "$raw_log_path_for_trap"

        if cat "$raw_log_path_for_trap" | perl -pe 's/\x1b(\[([0-9;?]*[a-zA-Z])|\].*?(\x07|\x1b\\))//g' | col -b > "$cleaned_local_log_path_for_trap"; then
            rm -f "$raw_log_path_for_trap" # Remove raw log after successful processing
            printf "EXIT_TRAP: Local log processed: %s\n" "$cleaned_local_log_path_for_trap"

            # Ensure the target directory exists (important for the move)
            if [ ! -d "$(dirname "$final_target_log_path_for_trap")" ]; then
                mkdir -p "$(dirname "$final_target_log_path_for_trap")"
            fi

            # Attempt to move the cleaned log to its final destination (foreground for reliability in trap)
            if [[ "$ZSH_LOG_DIRECTORY" == "${SHARE_MOUNT_TARGET}"* ]] && mountpoint -q "${SHARE_MOUNT_TARGET}" 2>/dev/null; then
                printf "EXIT_TRAP: Moving log to share: %s\n" "$final_target_log_path_for_trap"
                if mv "$cleaned_local_log_path_for_trap" "$final_target_log_path_for_trap"; then
                    printf "EXIT_TRAP: SUCCESS - Moved to share: %s\n" "$final_target_log_path_for_trap"
                else
                    printf "EXIT_TRAP: ERROR - Failed to move to share. Log remains in cache: %s\n" "$cleaned_local_log_path_for_trap"
                fi
            elif [[ "$ZSH_LOG_DIRECTORY" != "${LOCAL_SCRIPT_LOG_CACHE_DIR}"* ]]; then
                printf "EXIT_TRAP: Moving log to local destination: %s\n" "$final_target_log_path_for_trap"
                if mv "$cleaned_local_log_path_for_trap" "$final_target_log_path_for_trap"; then
                    printf "EXIT_TRAP: SUCCESS - Moved to local: %s\n" "$final_target_log_path_for_trap"
                else
                    printf "EXIT_TRAP: ERROR - Failed to move to local. Log remains in cache: %s\n" "$cleaned_local_log_path_for_trap"
                fi
            else
                printf "EXIT_TRAP: INFO - Log already in cache (final destination): %s\n" "$cleaned_local_log_path_for_trap"
            fi
        else
            printf "EXIT_TRAP: ERROR - Failed to process raw log: %s (Raw file preserved)\n" "$raw_log_path_for_trap"
        fi
        printf "--- Zsh Exit: Log Processing Complete ---\n"
    else
        # This message might appear if SCRIPT_LOG_ACTIVE was false or if the shell exits before _ZSH_SCRIPT_SESSION_RAW_LOG_PATH is set
        # printf "\n--- Zsh Exit: No active script log path found for this session. ---\n"
    fi
}

# Check terminal conditions for starting script logging
if [[ "$TERM" == "xterm"* || "$TERM" == "screen"* || "$TERM_PROGRAM" == "tmux" || -n "$TMUX" ]]; then # Added TMUX check
    # SCRIPT_LOG_ACTIVE is used to prevent `script` from starting again if we `exec zsh` or start a sub-shell
    # that also sources this .zshrc *within an already logged session*.
    if [ -z "$SCRIPT_LOG_ACTIVE" ]; then
        current_tty=$(tty 2>/dev/null) # Suppress tty error if not available (e.g. some non-interactive contexts)
        # Only start script in interactive pseudo-terminals
        if [[ -n "$current_tty" && ("$current_tty" == /dev/pts/* || "$current_tty" == /dev/ttyS*) ]]; then
            export SCRIPT_LOG_ACTIVE=1 # Mark that this Zsh process has initiated script logging

            local log_timestamp_suffix="$(date +%s)"
            local base_log_filename_for_session="${CURDATE}_${operator}_${HOSTNAME_SHORT}_${log_timestamp_suffix}_terminal"

            # Set the global path for the raw log file for this session
            _ZSH_SCRIPT_SESSION_RAW_LOG_PATH="${LOCAL_SCRIPT_LOG_CACHE_DIR}/${base_log_filename_for_session}.log.raw"
            
            # Set the EXIT trap *before* starting the script command
            # This function will be called when the *current* Zsh shell (the one sourcing .zshrc) exits.
            trap '_zsh_script_log_cleanup' EXIT

            printf "INFO: Starting logged terminal session. Raw output will be cached to: %s\n" "$_ZSH_SCRIPT_SESSION_RAW_LOG_PATH"
            printf "INFO: Log processing and move will occur when this main shell exits.\n"

            # Start script. The `script` command launches a new shell (defaulting to $SHELL, which is zsh).
            # When you type `exit` inside this new shell started by `script`, the `script` command finishes.
            # The original Zsh shell (that sourced this .zshrc) then continues.
            # The EXIT trap on the original Zsh shell will handle cleanup.
            if ! script -qf "$_ZSH_SCRIPT_SESSION_RAW_LOG_PATH"; then
                local script_exit_code=$?
                printf "ERROR: The 'script' command failed to start or exited abnormally (code %s).\n" "$script_exit_code"
                printf "       Raw log may not exist or is incomplete at: %s\n" "$_ZSH_SCRIPT_SESSION_RAW_LOG_PATH"
                # If script fails to start, we should clear the path so the trap doesn't try to process a non-existent/failed log
                _ZSH_SCRIPT_SESSION_RAW_LOG_PATH=""
                # Also unset SCRIPT_LOG_ACTIVE so a subsequent attempt (e.g. new shell) might work
                unset SCRIPT_LOG_ACTIVE 
                # Unset the trap as well if script didn't even run
                trap - EXIT
            fi
            # After `script` finishes (i.e., the sub-shell it launched exits),
            # control returns here to the parent Zsh.
            # The parent Zsh will eventually exit, triggering the `_zsh_script_log_cleanup` trap.
            # We unset SCRIPT_LOG_ACTIVE here because this *instance* of script logging has completed.
            # If this shell (the one that ran script) is exited and a new one starts, it should be able to log again.
            # However, the trap is on THIS shell. If this shell execs another zsh, the trap is gone.
            # The `export SCRIPT_LOG_ACTIVE=1` prevents nested `script` calls if you type `zsh` inside the `script`ed shell.
            # When the `script`ed shell exits, `SCRIPT_LOG_ACTIVE` is still set in the parent.
            # This is complex. The trap is on the *parent* shell.
            # The `SCRIPT_LOG_ACTIVE` prevents the *parent* shell from trying to start `script` again if it's re-sourced.
        fi
    fi
fi

# ==============================================================================
#                        END Standard Zsh Configuration
# ==============================================================================


# ==============================================================================
#                               DO NOT CHANGE!
#                         EDC (Engagement Data Collector)
#                           Client-Side Shell Functions
#                               DO NOT CHANGE!
# ==============================================================================

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
    response_body=$(curl -s -L -w '%{http_code}' \
        -X POST \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json' \
        -d "$json_payload" \
        "${token_url}")
    
    local curl_exit_status=$?
    if [[ "$curl_exit_status" -ne 0 ]]; then
        echo "Error: curl command failed with exit status ${curl_exit_status}. Could not connect?" >&2
        echo "Curl Error Output (if any): ${response_body}" >&2
        return 1
    fi

    # Extract HTTP code from the end of the response body
    http_code="${response_body: -3}"
    response_body="${response_body%???}"

    # Sanitize the response body
    if [[ -n "$response_body" ]]; then
        response_body=$(echo "$response_body" | tr -d '\r\n' | sed 's/[^[:print:][:space:]]//g' | tr -d '\000-\010\013\014\016-\037')
    fi

    if [[ "$http_code" -eq 200 ]]; then
        local token
        token=$(echo "$response_body" | jq -r '.token' 2>/dev/null)
        if [[ $? -eq 0 && -n "$token" && "$token" != "null" ]]; then
            echo "Success! Token obtained:"
            echo "$token"
            echo "You can now set it as an environment variable:"
            echo "export EDC_API_TOKEN=\"${token}\""
            return 0
        else
            echo "Error: Token request successful (HTTP 200), but no token found in response." >&2
            echo "Response Body:" >&2
            echo "$response_body" | jq '.' >&2
            return 1
        fi
    else
        echo "Error: Failed to obtain token (HTTP ${http_code})." >&2
        echo "Response Body:" >&2
        echo "$response_body" | jq '.' 2>/dev/null || echo "$response_body" >&2
        return 1
    fi
}

# Universal API request helper with response sanitization
_edc_api_request() {
    local method="$1"
    local url="$2"
    local json_data="$3" # Optional: for POST/PUT/PATCH
    local http_code
    local response_body
    local curl_opts=()
    local combined_output

    # Common options
    curl_opts+=(-s -L)
    curl_opts+=(-X "$method")
    curl_opts+=(-H "Authorization: Token ${EDC_API_TOKEN}")
    curl_opts+=(-H "Accept: application/json")

    # Add data for relevant methods
    if [[ "$method" == "POST" || "$method" == "PUT" || "$method" == "PATCH" ]]; then
        if [[ -z "$json_data" ]]; then
            echo "Error (_edc_api_request): JSON data required for $method." >&2
            return 1
        fi
        curl_opts+=(-H "Content-Type: application/json")
        curl_opts+=(-d "$json_data")
    fi

    # Add option to write status code AFTER the body
    curl_opts+=(-w '\n%{http_code}')

    # Execute curl
    combined_output=$(curl "${curl_opts[@]}" "${url}")
    local curl_exit_status=$?

    # --- Process output ---
    if [[ "$curl_exit_status" -ne 0 ]]; then
        echo "Error: curl command failed (URL: ${url}, Exit Status: ${curl_exit_status}). Could not connect?" >&2
        echo "$combined_output" >&2
        return 1
    fi

    http_code="${combined_output##*$'\n'}"
    response_body="${combined_output%$'\n'*}"

    if ! [[ "$http_code" =~ ^[0-9]+$ ]]; then
        echo "Error: Failed to parse HTTP status code from curl output." >&2; echo "Full curl output:" >&2; echo "$combined_output" >&2; return 1;
    fi

    ## *** Robustly sanitize the response body before any other processing ***
    if [[ -n "$response_body" ]]; then
        response_body=$(echo "$response_body" | tr -d '\r\n' | tr -d '\000-\010\013\014\016-\037' | sed 's/[^[:print:][:space:]]//g')
    fi

    ######### --- Handle Response based on HTTP Code ---
    if [[ "$http_code" -ge 200 && "$http_code" -lt 300 ]]; then
        if [[ "$method" != "HEAD" ]]; then
            # Now, check if the CLEANED body is valid JSON
            if echo "$response_body" | jq -e . > /dev/null 2>&1; then
                echo "$response_body" # Valid JSON, output as is
            else
                # Even after cleaning, it might be an empty body on a 201/204, which is fine
                if [[ -n "$response_body" ]]; then
                    echo "Warning: API response for $method $url (HTTP $http_code) was not valid JSON." >&2
                    echo "$response_body"
                fi
            fi
        fi
        return 0 # Success
    else
        echo "Error: API request failed (HTTP ${http_code})" >&2; echo "Response Body:" >&2
        # Try to pretty print if JSON, otherwise print raw cleaned body
        echo "$response_body" | jq '.' 2>/dev/null || echo "$response_body" >&2
        return 1 # Failure
    fi
}


# Helper function to fetch targets with response sanitization
_select_target_id() {
    # --- Config Checks ---
    if [[ -z "$EDC_API_URL" ]]; then echo "Error (_select_target_id): EDC_API_URL not set." >&2; return 1; fi
    if [[ -z "$EDC_API_TOKEN" ]]; then echo "Error (_select_target_id): EDC_API_TOKEN not set." >&2; return 1; fi
    if ! command -v jq &> /dev/null; then echo "Error (_select_target_id): jq not found." >&2; return 1; fi
    if ! command -v curl &> /dev/null; then echo "Error (_select_target_id): curl not found." >&2; return 1; fi

    local base_url="${EDC_API_URL%/}"
    local target_api_url="${base_url}/collector/api/targets/"
    local auth_header="Authorization: Token ${EDC_API_TOKEN}"

    echo "Fetching targets from API..." >&2
    local all_targets_json="[]" next_url="${target_api_url}"

    while [[ -n "$next_url" && "$next_url" != "null" ]]; do
        local response_body
        response_body=$(curl -s -L -H "${auth_header}" -H 'Accept: application/json' "${next_url}")
        local curl_exit_status=$?
        if [[ "$curl_exit_status" -ne 0 ]]; then
            echo "Error (_select_target_id): curl failed fetching targets (exit ${curl_exit_status})." >&2
            return 1
        fi

        # *** Sanitize the response immediately after receiving it ***
        if [[ -n "$response_body" ]]; then
            response_body=$(echo "$response_body" | tr -d '\r\n' | sed 's/[^[:print:][:space:]]//g' | tr -d '\000-\010\013\014\016-\037')
        fi

        # Now that it's clean, check if it's valid JSON before parsing
        if ! echo "$response_body" | jq -e . > /dev/null 2>&1; then
            echo "Error (_select_target_id): API response was not valid JSON." >&2
            echo "Response Body:" >&2
            echo "$response_body" >&2
            return 1
        fi

        local results
        results=$(echo "$response_body" | jq -c '.results')
        if [[ $? -ne 0 || -z "$results" || "$results" == "null" ]]; then
            echo "Error (_select_target_id): Could not parse '.results' from API response." >&2
            return 1
        fi

        all_targets_json=$(echo "$all_targets_json $results" | jq -c -s 'add')
        next_url=$(echo "$response_body" | jq -r '.next')
    done

    local target_count
    target_count=$(echo "$all_targets_json" | jq 'length')
    if [[ "$target_count" -eq 0 ]]; then
        echo "No targets found in the system." >&2
        return 1
    else
        target_ids=("${(@f)$(echo "$all_targets_json" | jq -r '.[].id')}")
        target_hostnames=("${(@f)$(echo "$all_targets_json" | jq -r '.[].hostname // "N/A"')}")
        target_ips=("${(@f)$(echo "$all_targets_json" | jq -r '.[].ip_address // "N/A"')}")
        echo "Found ${target_count} targets." >&2
    fi

    echo "Select Target:" >&2
    #echo "  [0] No Target" >&2
    if [[ "$target_count" -gt 0 ]]; then
        for i in $(seq 1 ${#target_ids[@]}); do
            printf "  [%d] %s (%s)\n" "${i}" "${target_hostnames[i]}" "${target_ips[i]}" >&2
        done
    fi

    local target_choice
    local final_selected_target_id=""
    while true; do
        read "target_choice?Enter target number [0-${target_count}]: "
        if [[ "$target_choice" =~ ^[0-9]+$ && "$target_choice" -ge 0 && "$target_choice" -le "$target_count" ]]; then
            if [[ "$target_choice" -ne 0 ]]; then
                if [[ "$target_choice" -le ${#target_ids[@]} ]]; then
                    final_selected_target_id="${target_ids[$target_choice]}"
                else
                    echo "Invalid choice (out of bounds for available targets)." >&2
                    continue
                fi
            fi
            break
        else
            echo "Invalid input. Please enter a number." >&2
        fi
    done

    echo "$final_selected_target_id" # This is the return value via stdout
    return 0
}


# Function to add or list Credentials
function cred {
    local username="" password="" service="" notes="" list_mode=false
    local OPTIND OPTARG
    OPTIND=1

    while getopts ":lu:p:s:n:h" option; do
        case $option in
            l) list_mode=true;;
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

    if [[ -z "$EDC_API_URL" ]]; then echo "Error: EDC_API_URL not set." >&2; return 1; fi
    if [[ -z "$EDC_API_TOKEN" ]]; then echo "Error: EDC_API_TOKEN not set." >&2; return 1; fi
    if ! command -v jq &> /dev/null; then echo "Error: jq not found." >&2; return 1; fi

    local base_url="${EDC_API_URL%/}"
    local cred_api_url="${base_url}/collector/api/credentials/"

    if [[ "$list_mode" == true ]]; then
        echo "Listing credentials (first page)..."
        local api_response
        if api_response=$(_edc_api_request GET "$cred_api_url"); then
            echo "$api_response" | jq '.results[] | {username, password_plaintext}'
            return 0
        else
            return 1
        fi
    fi

    if [[ -z "$username" ]] || [[ -z "$password" ]]; then
        echo "Error: Username (-u) and Password (-p) are required for adding." >&2
        cred_usage
        return 1
    fi

    local json_payload
    json_payload=$(jq -n --arg u "$username" --arg p "$password" --arg s "$service" --arg n "$notes" \
        '{username: $u, password_plaintext: $p, service: $s, notes: $n}')

    echo "Submitting credential for user '${username}'..."
    local api_response_add
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
    echo "    -l           : List existing credentials (shows first page)."
    echo "    -u USERNAME  : Username for adding a credential (required for add)."
    echo "    -p 'PASSWORD': Password/secret (required for add). Quote if needed."
    echo "    -s SERVICE   : Service the credential is for (optional)."
    echo "    -n NOTES     : Notes about the credential (optional). Quote if needed."
    echo "    -h           : Display this help message."
    echo "  Requires EDC_API_URL and EDC_API_TOKEN environment variables."
}


# Function to add or list Targets
function target {
    local ip="" host="" os="" desc="" list_mode=false
    local OPTIND OPTARG
    OPTIND=1

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

    if [[ -z "$EDC_API_URL" ]]; then echo "Error: EDC_API_URL not set." >&2; return 1; fi
    if [[ -z "$EDC_API_TOKEN" ]]; then echo "Error: EDC_API_TOKEN not set." >&2; return 1; fi
    if ! command -v jq &> /dev/null; then echo "Error: jq not found." >&2; return 1; fi

    local base_url="${EDC_API_URL%/}"
    local target_api_url="${base_url}/collector/api/targets/"

    if [[ "$list_mode" == true ]]; then
        echo "Listing targets (first page)..."
        local api_response
        if api_response=$(_edc_api_request GET "$target_api_url"); then
            echo "$api_response" | jq '.results[] | {ip_address, hostname}'
            return 0
        else
            return 1
        fi
    fi

    if [[ -z "$ip" && -z "$host" ]]; then
        echo "Error: At least IP Address (-i) or Hostname (-h) required for adding." >&2
        target_usage
        return 1
    fi

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
    echo "    -l             : List existing targets (shows first page)."
    echo "    -i IP_ADDRESS  : IP address for adding a target (required if -h omitted)."
    echo "    -h HOSTNAME    : Hostname for adding a target (required if -i omitted)."
    echo "    -o OS          : Operating System (optional)."
    echo "    -d DESCRIPTION : Description (optional). Quote if needed."
    echo "  Requires EDC_API_URL and EDC_API_TOKEN environment variables."
}


# Function to add or list Oplog Entries
function log {
    local list_mode=false
    local cmda="" desc=""
    local OPTIND=1

    while getopts ":lc:d:" option; do
        case $option in
            l) list_mode=true;;
            c) cmda=$OPTARG;;
            d) desc=$OPTARG;;
            \?) echo "Invalid option: -$OPTARG" >&2; log_help; return 1;;
            :) echo "Option -$OPTARG requires an argument." >&2; log_help; return 1;;
        esac
    done

    if [[ "$1" == "-l" ]]; then
        list_mode=true
    fi

    if [[ -z "$EDC_API_URL" ]]; then echo "Error: EDC_API_URL not set." >&2; return 1; fi
    if [[ -z "$EDC_API_TOKEN" ]]; then echo "Error: EDC_API_TOKEN not set." >&2; return 1; fi
    if ! command -v jq &> /dev/null; then echo "Error: jq not found." >&2; return 1; fi

    local base_url="${EDC_API_URL%/}"
    local oplog_api_url="${base_url}/collector/api/oplog/"
    local auth_header="Authorization: Token ${EDC_API_TOKEN}"

    if [[ "$list_mode" == true ]]; then
        echo "Listing Oplog entries (first page)..."
        local api_response
        if api_response=$(_edc_api_request GET "$oplog_api_url"); then
            echo "$api_response" | tr -d '\r\n' | tr -d '\000-\010\013\014\016-\037' | sed 's/[^[:print:][:space:]]//g' | jq '.results[] | {id, target, command, notes}'
            #echo "$api_response" | tr -d '\000-\010\013\014\016-\037' | sed 's/[^[:print:][:space:]]//g' | jq --join-output '.results[] | "ID: ", .id, "\n", "Target: ", .target, "\n", "Command: ", .command, "\n", "Notes: ", .notes, "\n---\n"'
            return 0
        else
            return 1
        fi
    fi

    OPTIND=1
    cmda="" desc=""
    while getopts ":c:d:" option; do
        case $option in
            c) cmda=$OPTARG;;
            d) desc=$OPTARG;;
        esac
    done
    shift $((OPTIND -1))

    if [[ -z "$cmda" ]]; then
        echo "Error: Command (-c) is required for adding an Oplog entry." >&2
        log_help
        return 1
    fi

    if [[ -z "$operator" ]]; then echo "Warning: 'operator' not set, using 'unknown'." >&2; operator="unknown"; fi
    local sip; if command -v my_ip &> /dev/null; then sip=$(my_ip); else echo "Warning: my_ip not found." >&2; sip="127.0.0.1"; fi
    local shost; shost=$(hostname); local tool="terminal"
    if ! command -v tee &> /dev/null; then echo "Error: 'tee' command not found." >&2; return 1; fi

    local selected_target_id
    selected_target_id=$(_select_target_id)
    if [[ $? -ne 0 ]]; then return 1; fi

    local oput file now
    echo -e "\n\n--- Executing Command ---\n>>> ${cmda}\n--- Output ---"
    oput=$(eval $cmda 2>&1 | tee /dev/tty)
    echo -e "--- Command Finished ---\n\n"

    # Sanitize commands before submission
    oput2=$(echo "$oput" | sed -E 's/\x1B\[[0-9;]*[mK]//g')
    oput3=$(echo "$oput2" | tr -d '\000-\010\013\014\016-\037')
    oput4=$(echo "$oput3" | sed 's/[^[:print:][:space:]]//g')
    oput5=$(echo "$oput4" | tr -d '\r\n')


    now=$(TZ=UTC date +%Y%m%d_%H%M%S); file="/tmp/${now}_${operator}_${desc}.png"
    screenshot_opts=(); if command -v import &> /dev/null; then echo "Taking screenshot (wait 1s)..."; sleep 1; import -window root "$file"; if [[ $? -eq 0 ]]; then echo ""; else echo "Warning: Screenshot failed." >&2; file=""; fi; else file=""; fi


    # --- Build and Execute curl POST Command ---
    echo "--- Submitting Oplog Entry ---" >&2
    local curl_opts=()
    curl_opts+=(-s -L -X POST -H "${auth_header}")
    curl_opts+=(-F "command=$cmda")
    curl_opts+=(-F "output=$oput5")
    curl_opts+=(-F "src_host=$shost")
    curl_opts+=(-F "src_ip=$sip")
    curl_opts+=(-F "tool=$tool")
    if [[ -n "$selected_target_id" ]]; then curl_opts+=(-F "target_id=$selected_target_id"); fi
    if [[ -n "$desc" ]]; then curl_opts+=(-F "notes=$desc"); fi
    if [[ -n "$file" && -f "$file" ]]; then
        echo "  -> Attaching screenshot for upload..." >&2
        curl_opts+=(-F "screenshot=@$file")
    fi
    curl_opts+=(-w '\n%{http_code}')

    local combined_output
    combined_output=$(curl "${curl_opts[@]}" "${oplog_api_url}")
    local post_curl_exit_status=$?

    # --- Process Response ---
    if [[ "$post_curl_exit_status" -ne 0 ]]; then
         echo "Error: curl failed submitting oplog (exit status ${post_curl_exit_status})." >&2
         if [[ -n "$file" && -f "$file" ]]; then rm "$file"; fi; return 1;
    fi

    local post_http_code="${combined_output##*$'\n'}"
    local post_response_body="${combined_output%$'\n'*}"

    if ! [[ "$post_http_code" =~ ^[0-9]+$ ]]; then
        echo "Error: Failed to parse HTTP status code." >&2; echo "Full Output: $combined_output" >&2
        if [[ -n "$file" && -f "$file" ]]; then rm "$file"; fi; return 1;
    fi

    if [[ "$post_http_code" -eq 201 ]]; then
        echo "Oplog entry created successfully (HTTP ${post_http_code})." >&2
    else
        echo "Error: Failed to create oplog entry (HTTP ${post_http_code})." >&2
        echo "Response Body:" >&2
        echo "$post_response_body" | tr -d '\r\n' | sed 's/[^[:print:][:space:]]//g' | tr -d '\000-\010\013\014\016-\037' | jq '.' 2>/dev/null || echo "$post_response_body" >&2
        if [[ -n "$file" && -f "$file" ]]; then rm "$file"; fi; return 1;
    fi

    if [[ -n "$file" && -f "$file" ]]; then
        echo "  -> Cleaning up temporary screenshot: $file" >&2
        rm "$file"
    fi
    return 0
}

log_help() {
    echo "Usage: log -l | log -c 'command to execute' [-d 'description']"
    echo "  Adds or lists Oplog entries via the EDC API."
    echo "  Options:"
    echo "    -l           : List existing Oplog entries (shows first page)."
    echo "    -c COMMAND   : Command that was executed (required for add)."
    echo "    -d DESCRIPTION: Simple description for the log entry/screenshot."
    echo "  Requires EDC_API_URL and EDC_API_TOKEN environment variables."
}


# Function to add or list Enumeration Data
function enum {
    local scan_type="" desc="" notes="" scan_file_path="" list_mode=false
    local OPTIND OPTARG
    OPTIND=1

    while getopts ":lt:d:n:f:h" option; do
        case $option in
            l) list_mode=true;;
            t) scan_type=$OPTARG;;
            d) desc=$OPTARG;;
            n) notes=$OPTARG;;
            f) scan_file_path=$OPTARG;;
            h) enum_usage; return 0;;
            \?) echo "Invalid option: -$OPTARG" >&2; enum_usage; return 1;;
            :) echo "Option -$OPTARG requires an argument." >&2; enum_usage; return 1;;
           esac
    done
    shift $((OPTIND -1))

    if [[ -z "$EDC_API_URL" ]]; then echo "Error: EDC_API_URL not set." >&2; return 1; fi
    if [[ -z "$EDC_API_TOKEN" ]]; then echo "Error: EDC_API_TOKEN not set." >&2; return 1; fi
    if ! command -v jq &> /dev/null; then echo "Error: jq not found." >&2; return 1; fi
    if ! command -v curl &> /dev/null; then echo "Error: curl not found." >&2; return 1; fi

    local base_url="${EDC_API_URL%/}"
    local enum_api_url="${base_url}/collector/api/enumdata/"
    local auth_header="Authorization: Token ${EDC_API_TOKEN}"

    if [[ "$list_mode" == true ]]; then
        if [[ -n "$scan_type" || -n "$desc" || -n "$notes" || -n "$scan_file_path" ]]; then
             echo "Error: Cannot use other options with -l (list mode)." >&2
             enum_usage
             return 1
        fi
        echo "Listing Enumeration Data entries (first page)..."
        local api_response
        if api_response=$(_edc_api_request GET "$enum_api_url"); then
            echo "$api_response" | jq '.'
            return 0
        else
            return 1
        fi
    fi

    # For add mode, at least one option should be provided
    if [[ -z "$scan_type" && -z "$desc" && -z "$notes" && -z "$scan_file_path" ]]; then
        echo "Error: At least one option (-t, -d, -n, or -f) is required to add an entry." >&2
        enum_usage
        return 1
    fi

    local selected_target_id
    selected_target_id=$(_select_target_id)
    if [[ $? -ne 0 ]]; then
        return 1
    fi

    echo "--- Submitting Enumeration Data Entry ---" >&2
    local curl_opts=()
    curl_opts+=(-s -L -X POST)
    curl_opts+=(-H "${auth_header}")

    if [[ -n "$scan_type" ]]; then curl_opts+=(-F "scan_type=$scan_type"); fi
    if [[ -n "$desc" ]]; then curl_opts+=(-F "description=$desc"); fi
    if [[ -n "$notes" ]]; then curl_opts+=(-F "notes=$notes"); fi
    if [[ -n "$selected_target_id" ]]; then curl_opts+=(-F "target_id=$selected_target_id"); fi

    if [[ -n "$scan_file_path" ]]; then
        if [[ -f "$scan_file_path" ]]; then
            echo "  Attaching scan file: $scan_file_path" >&2
            curl_opts+=(-F "scan_file=@$scan_file_path")
        else
            echo "Warning: Scan file path '$scan_file_path' not found. Skipping file upload." >&2
        fi
    fi

    curl_opts+=(-w '\n%{http_code}')

    local combined_output
    combined_output=$(curl "${curl_opts[@]}" "${enum_api_url}")
    local post_curl_exit_status=$?

    if [[ "$post_curl_exit_status" -ne 0 ]]; then echo "Error: curl command failed submitting enum data (exit status ${post_curl_exit_status})." >&2; echo "Curl output: $combined_output" >&2; return 1; fi
    
    local post_http_code="${combined_output##*$'\n'}"
    local post_response_body="${combined_output%$'\n'*}"

    if ! [[ "$post_http_code" =~ ^[0-9]+$ ]]; then echo "Error: Failed to parse HTTP status code." >&2; echo "Full Output: $combined_output" >&2; return 1; fi

    if [[ "$post_http_code" -eq 201 ]]; then
        echo "Success! Enumeration data entry created (HTTP ${post_http_code})." >&2
        echo "Response:"
        echo "$post_response_body" | tr -d '\r\n' | sed 's/[^[:print:][:space:]]//g' | tr -d '\000-\010\013\014\016-\037' | jq '.'
    else
        echo "Error: Failed to create enumeration data entry (HTTP ${post_http_code})." >&2
        echo "Response Body:" >&2
        echo "$post_response_body" | tr -d '\r\n' | sed 's/[^[:print:][:space:]]//g' | tr -d '\000-\010\013\014\016-\037' | jq '.' 2>/dev/null || echo "$post_response_body" >&2
        return 1
    fi
    return 0
}

enum_usage() {
    echo "Usage: enum -l | enum [-t <type>] [-d <desc>] [-n <notes>] [-f <filepath>] [-h]"
    echo "  Adds or lists Enumeration Data entries via the EDC API."
    echo "  Add mode will prompt for target selection."
    echo "  Options:"
    echo "    -l           : List existing enum data entries (shows first page)."
    echo "    -t TYPE      : Type of scan/enum (optional, e.g., Nmap, Nessus)."
    echo "    -d DESC      : Brief description (optional). Quote if needed."
    echo "    -n NOTES     : Detailed notes (optional). Quote if needed."
    echo "    -f FILEPATH  : Path to a local scan file to upload (optional)."
    echo "    -h           : Display this help message."
    echo "  Requires EDC_API_URL and EDC_API_TOKEN environment variables."
}
