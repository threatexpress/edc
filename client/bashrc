# ~/.bashrc: executed by bash(1) for non-login shells.
# This script is written to support multiple *nix flavors.
# If you use a single build, feel free to remove the "fluff" on your system

operator=james
opid=5
UToken="enteryourtokeninsidequoteshere"
edcp=https
edc=domain.com

#Uncomment to set shell for close after 240 seconds
#This is useful for maintaining shorter log files
#TMOUT=240

case $- in
    *i*) ;;
      *) return;;
esac

HISTCONTROL=ignoreboth
HISTSIZE=1000
HISTFILESIZE=2000
HISTTIMEFORMAT='%Y%m%d_%H%M%S_%zUTC '

shopt -s histappend
shopt -s checkwinsize

if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

case "$TERM" in
    xterm-color) color_prompt=yes;;
esac

force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
        color_prompt=yes
    else
        color_prompt=
    fi
fi

if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;31m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ '
else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
fi
unset color_prompt force_color_prompt

case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias dir='dir --color=auto'
    alias vdir='vdir --color=auto'

    alias grep='grep --color'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
    alias ls='ls -G --color=auto'
    alias ll='ls -alF --color=auto'
    alias la='ls -AalhG --color=auto'
    alias lg='ls -AalhG --color=auto |grep $1'
    alias l='ls -CF --color=auto'
    alias el='sudo $(history -p \!\!)'
    alias level='echo $SHLVL'
fi

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi


function mkcd() {
    mkdir -p "$@"
    cd "$@"
}

# Chrome - User
if [ ! -d ~/.chrome_user ]; then
    mkdir ~/.chrome_user
fi
alias chromium="chromium --user-data-dir ~/.chrome_user"

CURDATE=`date '+%Y%m%d_%H%M%S.%N_%Z'`

function my_ip {
#    /sbin/ifconfig eth0 | grep 'inet addr:' | cut -d: -f2 | awk '{ print $1}'
    /sbin/ifconfig eth0 | grep 'inet ' | awk '{ print $2}'
#    ipconfig getifaddr en0
}
if [ ! -d $HOME/logs ]; then
    mkdir $HOME/logs 2> /dev/null
fi

function log_help {
    echo
    echo Usage: $0 [ options...]
    echo
    echo "log -l attackubuntu1 -k 43.44.54.55 -t tgthost1 -i 192.168.0.1 -p 445 -u http://www.news.com -n terminal -s screenshot_desc -d 'desc of action here' -c 'ping -c1 www.news.com'"
    echo
    echo '    -t, (Required= target) "target hostname"'
    echo '    -i, (Required= ip) "target ip address"'
    echo '    -p, (Required= port) "target ip address"'
    echo '    -u, (Target URL) "url command affects"'
    echo '    -s, (Screenshot Description) "short_screenshot_description"'
    echo '    -n, (Tool) "terminal"'
    echo '    -d, (Description) "Log Description"'
    echo '    -l, (Source Host) "Passes hostname if omitted"'
    echo '    -k, (Source IP) "Passes local ip if omitted"'
    echo '    -c, (Commands) "command string'
    echo
    echo Use with -c only for interactive prompts.
    return
}


function target_help {
    echo
    echo Usage: $0 [ options...]
    echo
    echo target -t tgthost1 -i 192.168.0.1 -n net5 -u admin -d adminwks -c access to all segments
    echo
    echo '    -t, (Required= target) "target hostname"'
    echo '    -i, (ip) "target ip address"'
    echo '    -n, (Network) "network info"'
    echo '    -u, (Target username) "username"'
    echo '    -d, (Description) "System Description"'
    echo '    -c, (Comments) "Useful Comments'
    echo
    echo Use target without options for interactive prompts.
    return
}

function cred_help {
    echo
    echo Usage: $0 [ options...]
    echo
    echo cred -u cmduser4 -p cmdpass4 -n hashgoeshere -t cmdu4:jaldkjsfldsjf -k /home/james/Desktop/token1.tkn -f charlie -l migo -r users -d keyboarder 
    echo
    echo '    -u, (Required= Username) "target username"'
    echo '    -p, (Password) "usser password"'
    echo '    -n, (Hash) "userhash"'
    echo '    -t, (Token String) "cmdu4:somedatahere"'
    echo '    -k, (Token File Path) "/full/path/to/file"'
    echo '    -f, (First Name) "Charlie"'
    echo '    -l, (Last Name) "Migo"'
    echo '    -r, (Role or Position) "User"'
    echo '    -d, (Description) "Useful description'
    echo
    echo Use cred without options for interactive prompts.
    return
}

function log {
    operator=$operator
    sip=$(my_ip)
    shost=`hostname`
    tool=terminal

    if [[ $# -lt 1 ]]; then
        log_help
    else
        local OPTIND
        while getopts "ht:i:p:u:s:c:n:d:l:k:" option; do
            case $option in
            h) log_help && return 1;;
            t) dhost=$OPTARG;;
            i) dip=$OPTARG;;
            p) dport=$OPTARG;;
            u) durl=$OPTARG;;
            s) ssdesc=$OPTARG;;
            c) cmda=$OPTARG;;
            n) tool=$OPTARG;;
            d) desc=$OPTARG;;
            l) shost=$OPTARG;;
            k) sip=$OPTARG;;
            *) log_help && return 1;;
            esac
        done
        
        if [[ -z "$cmda" ]]; then
            printf "\nExample: log -c 'ping www.news.com'\n\n"
        fi


        if [[ -z "$dhost" ]]; then
            read -p "Enter Destination Host: " dhost
            read -p "Enter Desination IP: " dip
            read -p "Destination Port: " dport
            read -p "URL: " durl
            read -p "short_screenshot_description, example: user_login:  " ssdesc
        fi
    fi

        if [[ "$cmda" && "$dhost" && "$dip" && "$dport" ]]; then
            oput=$($cmda 2>&1 | tee /dev/tty)
            now=$(TZ=UTC-10 date +%Y%m%d_%H%M%S)
            file=$now"_"$ssdesc"_"$operator".png"
            sleep 2
            gnome-screenshot -w -f $file
            sleep 1
            curl -F "src_host=$shost" -F "src_ip=$sip" -F "dst_host=$dhost" -F "dst_ip=$dip" -F "dst_port=$dport" -F "url=$durl" -F "tool=$tool" -F "cmds=$cmda" -F "output=$oput" -F "scrsht=@$file" -F "operator_id=$opid" -H "Authorization: Token $UToken" $edcp://$edc/oplog/
        
            printf "\n\nScreenshot File: "$file"\n"
        else
            return
        fi

    dhost=""
    dip=""
    dport=""
    durl=""
    ssdesc=""
    desc=""
    oput=""
    cmda=""
}

function target() {
    if [[ $# -lt 1 ]]; then
        read -p "Host (Required): " tgthost
        read -p "Enter IP (Required): " tgtip
        read -p "Enter network: " tgtnet
        read -p "Enter any known users:  " tgtuser
        read -p "Host Description: " tgtdesc
        read -p "Comments: " tgtcomms
    fi

    if [[ $# -ge 1 ]]; then
        local OPTIND
        while getopts "ht:i:n:u:d:c:" option; do
           case $option in
            h) target_help ;;
            t) tgthost=$OPTARG;;
            i) tgtip=$OPTARG;;
            n) tgtnet=$OPTARG;;
            u) tgtuser=$OPTARG;;
            d) tgtdesc=$OPTARG;;
            c) tgtcomms=$OPTARG;;
            *) target_help;;
            esac
        done
    fi

    if [[ -z "$tgthost" && "tgtip" ]]; then
        echo "Please enter target and ip"
    else
        curl -d "host=$tgthost&ip=$tgtip&network=$tgtnet&users=$tgtuser&description=$tgtdesc&comments=$tgtcomms" $edcp://$edc/target/ -H "Authorization: Token $UToken"
    fi

    tgthost=""
    tgtip=""
    tgtnet=""
    tgtuser=""
    tgtdesc=""
    tgtcomms=""
}

function cred {
    if [[ $# -lt 1 ]]; then
        read -p "Enter username (Required): " creduser
        read -p "Enter password: " credpass
        read -p "Enter hash: " credhash
        read -p "Enter token: " credtoken
        read -p "Enter token file location: " credtknfile
        read -p "Enter First name: " credfirst
        read -p "Enter Last name: " credlast
        read -p "Enter role or position: " credrole
        read -p "Enter description: " creddesc
    fi

    if [[ $# -ge 1 ]]; then
        local OPTIND
        while getopts "hu:p:n:t:k:f:l:r:d:" option; do
           case $option in
            h) cred_help ;;
            u) creduser=$OPTARG;;
            p) credpass=$OPTARG;;
            n) credhash=$OPTARG;;
            t) credtoken=$OPTARG;;
            k) credtknfile=$OPTARG;;
            f) credfirst=$OPTARG;;
            l) credlast=$OPTARG;;
            r) credrole=$OPTARG;;
            d) creddesc=$OPTARG;;
            *) cred_help;;
            esac
        done
    fi

    if [[ -z "$creduser" ]]; then
        echo "Please enter username"
    else
        if [[ -z "$credtknfile" ]]; then
            curl -F "username=$creduser" -F "passwd=$credpass" -F "hashw=$credhash" -F "token=$credtoken" -F "first=$credfirst" -F "last=$credlast" -F "role=$credrole" -F "description=$creddesc" $edcp://$edc/cred/ -H "Authorization: Token $UToken"
        else
            curl -F "username=$creduser" -F "passwd=$credpass" -F "hashw=$credhash" -F "token=$credtoken" -F "tknfile=@$credtknfile" -F "first=$credfirst" -F "last=$credlast" -F "role=$credrole" -F "description=$creddesc" $edcp://$edc/cred/ -H "Authorization: Token $UToken"
        fi
    fi

    creduser=""
    credpass=""
    credhash=""
    credtoken=""
    credtknfile=""
    credfirst=""
    credlast=""
    credrole=""
    creddesc=""
}

function mount_tools() {
    TOOLSDIR="/tools"
    if [ -f "$HOME/.toolspw" ]; then
        mountphrase=$(cat ${HOME}/.toolspw)
    else
        echo -n "Mount passphrase: "
        read -s mountphrase
    fi
    printf "%s" "${mountphrase}" | ecryptfs-add-passphrase > /tmp/tmp.txt
    sig=`tail -1 /tmp/tmp.txt | awk '{print $6}' | sed 's/\[//g' | sed 's/\]//g'`
    rm -f /tmp/tmp.txt
    mount -t ecryptfs -o key=passphrase:passphrase_passwd=${mountphrase},no_sig_cache=yes,verbose=no,ecryptfs_fnek_sig=${sig},ecryptfs_sig=${sig},ecryptfs_cipher=aes,ecryptfs_key_bytes=16,ecryptfs_passthrough=no,ecryptfs_enable_filename_crypto=yes $TOOLSDIR $TOOLSDIR
    unset mountphrase
}

alias unmount_tools="umount /tools"


function mount_data() {
    DATADIR="/data"
    if [ -d "/data" ]; then
        echo "/data exist"
    else
        echo "Creating /data"
        mkdir "/data"
    fi
    if [ -f "$HOME/.datapw" ]; then
        mountphrase=$(cat ${HOME}/.datapw)
    else
        echo -n "Mount passphrase: "
        read -s mountphrase
    fi
    printf "%s" "${mountphrase}" | ecryptfs-add-passphrase > /tmp/tmp.txt
    sig=`tail -1 /tmp/tmp.txt | awk '{print $6}' | sed 's/\[//g' | sed 's/\]//g'`
    rm -f /tmp/tmp.txt
    mount -t ecryptfs -o key=passphrase:passphrase_passwd=${mountphrase},no_sig_cache=yes,verbose=no,ecryptfs_fnek_sig=${sig},ecryptfs_sig=${sig},ecryptfs_cipher=aes,ecryptfs_key_bytes=16,ecryptfs_passthrough=no,ecryptfs_enable_filename_crypto=yes $DATADIR $DATADIR
    unset mountphrase
    if [ -d "/data/admin" ]; then
        ls /data
    else
        mkdir /data/admin /data/osint /data/recon /data/targets /data/screeshots /data/payloads /data/logs
    fi
}

alias unmount_data="umount /data"


function enable_teamserver() {
    echo "Make sure to set your parameters in /etc/default/teamserver"
    ln -s /lib/systemd/system/teamserver.service /etc/systemd/system/teamserver.service
    ln -s /lib/systemd/system/teamserver.service /etc/systemd/system/multi-user.target.wants/teamserver.service
    /bin/systemctl daemon-reload
    echo "To start, use 'systemctl start teamserver'"
}

function disable_teamserver() {
    systemctl stop teamserver
    rm /etc/systemd/system/teamserver.service /etc/systemd/system/multi-user.target.wants/teamserver.service
    /bin/systemctl daemon-reload
}

alias ext_ip="curl ifconfig.me"

function win_shutdown() {
    net rpc shutdown -I $1 -U $2%$3
}

alias netstati="lsof -P -i -n"

function termss() {
    local dt=$(date '+%Y%m%d_%H%M%S.%N_%Z')
    $1 | /usr/bin/convert -font "FreeMono" label:@- $HOME/logs/screenshots/${dt}_terminal_screenshot.png
}

function start_capture() {
    local pid=$HOME/logs/pcaps/current.pid
    if [ -f $pid ]; then
        if pgrep -F $pid; then
            echo "tcpdump is currently running for this user. Please stop it first."
            return
        fi
    fi
    [ ! -d $HOME/logs/pcaps ] && mkdir -p $HOME/logs/pcaps
    local dt=$(date '+%Y%m%d_%H%M%S.%N_%Z')
    /usr/bin/nohup tcpdump -i $1 -s0 -v -w $HOME/logs/pcaps/${dt}_capture_$1.pcap > /dev/null 2>&1 & echo $! > $pid
    echo "tcpdump started."
}

function stop_capture() {
    local pid=$HOME/logs/pcaps/current.pid
    if [ -f $pid ]; then
        if pgrep -F $pid; then
            kill -15 $(cat $pid)
            echo "tcpdump stopped."
            return
        fi
    else
        echo "tcpdump is not currently running."
    fi
}

[ ! -d $HOME/logs/screenshots ] && mkdir -p $HOME/logs/screenshots
[ ! -d $HOME/logs/terminals ] && mkdir -p $HOME/logs/terminals

# Colors
BLACK=$(tput setaf 0)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
MAGENTA=$(tput setaf 5)
CYAN=$(tput setaf 6)
WHITE=$(tput setaf 7)
BRIGHT=$(tput bold)
NORMAL=$(tput sgr0)
BLINK=$(tput blink)
REVERSE=$(tput smso)
UNDERLINE=$(tput smul)

PS1="\n\[$WHITE\]╭ [\$(if [[ \$? == 0 ]]; then echo \"\[$GREEN\]✓\"; else echo \"\[$RED\]✕\"; fi) \[$WHITE\]\[$YELLOW\]\D{%Y%m%d_%H%M%S_%zUC} \[$WHITE\]\u@\h \[${CYAN}\]$(my_ip)\[$BLUE\]: \[$WHITE\]]\n├ [\[$GREEN\]\w\[$WHITE\]]\n\[$WHITE\]╰ \$ "

array=("gnome-terminal-" "gnome-terminal" "tmux" "termin" "terminal" "x-term" "term" "xterm" "konsole" "lxterm" "uxterm" "xterm-256color" "xfce4-terminal" "sudo")  
search_string=`basename $(ps -f -p $PPID -o comm=)` 
match=$(echo "${array[@]:0}" | grep -o $search_string)  

if [[ $TERM == "xterm"* ]] && [[ ! -z $match ]]; then
    logname="${HOME}/logs/terminals/${CURDATE}.terminal.log"
    printf "This is a logged terminal session....\n"
    script -f ${logname}.raw
    cat ${logname}.raw | perl -pe 's/\e([^\[\]]|\[.*?[a-zA-Z]|\].*?\a)//g' | col -b > ${logname}
    exit
fi