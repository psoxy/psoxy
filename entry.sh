#!/bin/bash
export SOCKS_PORT=4040
export PSOXY_PORT=$LOCAL_PORT
echo "Psoxy port set to: $PSOXY_PORT"
: "${PORT:=80}"
: "${UUID:="00000000-0000-0000-0000-000000000000"}"
: "${X_PATH:="ui"}"
: "${NETWORK:="ws"}"
: "${P:="vmess"}"
#-------------------------------------------------------------------------
: "${CP:="vmess"}"
: "${CADDR:="localhost"}"
: "${CHOST:="localhost"}"
: "${CUUID:="00000000-0000-0000-0000-000000000000"}"
: "${CPORT:="80"}"
: "${CNETWORK:="ws"}"
: "${CTLS:=""}"
: "${CX_PATH:="ui"}"
#-------------------------------------------------------------------------
: "${WG:="NO"}"
: "${OUT:="proxychain"}"
if [ ${WG} == 'NO' ]; then
    echo '****WARP Disabled****'
    export OUTWG=$OUT
else
    : "${OUTWG:="proxywg"}"
fi
#--------------------------------------
export IFS=":"
export VARS='$PSOXY_PORT:$SOCKS_PORT:$OUTWG:$PORT:$UUID:$X_PATH:$NETWORK:$CADDR:$CHOST:$CUUID:$CPORT:$CNETWORK:$CX_PATH:$OUT:$CTLS:$CP:$P'
for i in $VARS
do
   export `echo $i | cut -d $ -f 2`
   echo $i:`echo $i | envsubst`
done
unset IFS
mkdir -p /tmp
envsubst $VARS < /etc/_config.json.var > /tmp/config.json
mkdir -p /tmp/per
cp /root/wirefan /tmp/per/
cp /root/testwarp.sh /tmp/
cd /tmp/per
if [ ${WG} == 'NO' ]; then
    echo '****NO-WARP****'
    # exec /tmp/per/wirefan -mode socks -bind 127.0.0.1:$SOCKS_PORT > /tmp/per/wg_logs.log 2> /tmp/per/wg_logs.log &
else
    echo $WG | base64 -d > /tmp/per/wg.conf
    exec /tmp/per/wirefan --wg-conf=/tmp/per/wg.conf -mode wire -bind 127.0.0.1:$SOCKS_PORT > /tmp/per/wg_logs.log 2> /tmp/per/wg_logs.log &
fi
exec /usr/bin/xray -c /tmp/config.json
