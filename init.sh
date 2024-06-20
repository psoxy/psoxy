#!/bin/bash

cp config-template.py config.py

if [[ ! -z $LOCAL_ADDR ]]; then
    echo "LOCAL_ADDR=$LOCAL_ADDR"
    sed -i -e "s/ENV_LOCAL_ADDR/\"$LOCAL_ADDR\"/g" config.py
else
    LOCAL_ADDR=0.0.0.0
    echo "LOCAL_ADDR=$LOCAL_ADDR"
    sed -i -e "s/ENV_LOCAL_ADDR/\"$LOCAL_ADDR\"/g" config.py
fi

if [[ ! -z $LOCAL_PORT ]]; then
    echo "LOCAL_PORT=$LOCAL_PORT"
    sed -i -e "s/ENV_LOCAL_PORT/$LOCAL_PORT/g" config.py
else
    LOCAL_PORT=2152
    echo "LOCAL_PORT=$LOCAL_PORT"
    sed -i -e "s/ENV_LOCAL_PORT/$LOCAL_PORT/g" config.py
fi

if [[ ! -z $REMOTE_ADDR ]]; then
    echo "REMOTE_ADDR=$REMOTE_ADDR"
    sed -i -e "s/ENV_REMOTE_ADDR/\"$REMOTE_ADDR\"/g" config.py
else
    REMOTE_ADDR="127.0.0.1"
    echo "REMOTE_ADDR=$REMOTE_ADDR"
    sed -i -e "s/ENV_REMOTE_ADDR/\"$REMOTE_ADDR\"/g" config.py
fi

if [[ ! -z $REMOTE_PORT ]]; then
    echo "REMOTE_PORT=$REMOTE_PORT"
    sed -i -e "s/ENV_REMOTE_PORT/$REMOTE_PORT/g" config.py
else
    REMOTE_PORT=2153
    echo "REMOTE_PORT=$REMOTE_PORT"
    sed -i -e "s/ENV_REMOTE_PORT/$REMOTE_PORT/g" config.py
fi

if [[ ! -z $LOCAL_UUID ]]; then
    echo "LOCAL_UUID=$LOCAL_UUID"
    sed -i -e "s/ENV_LOCAL_UUID/\"$LOCAL_UUID\"/g" config.py
else
    LOCAL_UUID=b050bc40-d8be-45df-aabc-60e0515d935a
    echo "LOCAL_UUID=$LOCAL_UUID"
    sed -i -e "s/ENV_LOCAL_UUID/\"$LOCAL_UUID\"/g" config.py
fi

if [[ ! -z $REMOTE_UUID ]]; then
    echo "REMOTE_UUID=$REMOTE_UUID"
    sed -i -e "s/ENV_REMOTE_UUID/\"$REMOTE_UUID\"/g" config.py
else
    REMOTE_UUID=b050bc40-d8be-45df-aabc-60e0515d935a
    echo "REMOTE_UUID=$REMOTE_UUID"
    sed -i -e "s/ENV_REMOTE_UUID/\"$REMOTE_UUID\"/g" config.py
fi

if [[ ! -z $MOCK_ADDR ]]; then
    echo "MOCK_ADDR=$MOCK_ADDR"
    sed -i -e "s/ENV_MOCK_ADDR/\"$MOCK_ADDR\"/g" config.py
else
    MOCK_ADDR=0.0.0.0
    echo "MOCK_ADDR=$MOCK_ADDR"
    sed -i -e "s/ENV_MOCK_ADDR/\"$MOCK_ADDR\"/g" config.py
fi

if [[ ! -z $MOCK_PORT ]]; then
    echo "MOCK_PORT=$MOCK_PORT"
    sed -i -e "s/ENV_MOCK_PORT/$MOCK_PORT/g" config.py
else
    MOCK_PORT=5000
    echo "MOCK_PORT=$MOCK_PORT"
    sed -i -e "s/ENV_MOCK_PORT/$MOCK_PORT/g" config.py
fi

if [[ ! -z $MOCK_TEST ]]; then
    echo "MOCK_TEST=$MOCK_TEST"
    sed -i -e "s/ENV_MOCK_TEST/\"$MOCK_TEST\"/g" config.py
else
    MOCK_TEST=default
    echo "MOCK_TEST=$MOCK_TEST"
    sed -i -e "s/ENV_MOCK_TEST/\"$MOCK_TEST\"/g" config.py
fi

if [[ ! -z $MODE ]]; then
    if [[ $MODE == server ]]; then
        python -u /app/psoxy-server.py -c
    elif [[ $MODE == relay ]]; then
        python -u /app/psoxy-relay.py -c
    elif [[ $MODE == client ]]; then
        python -u /app/psoxy-client.py -c
    elif [[ $MODE == mock-client ]]; then
        python -u /app/client.py -c
    elif [[ $MODE == mock-server ]]; then
        echo flask --app server run --host $LOCAL_ADDR --port $LOCAL_PORT
        flask --app server run --host $LOCAL_ADDR --port $LOCAL_PORT
    else
        echo "No such mode: $MODE"
        exit 1
    fi
else
    python -u /app/psoxy-server.py -c
fi

