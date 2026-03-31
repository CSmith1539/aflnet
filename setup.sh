export AFLNET=$(pwd)
export WORKDIR=$(pwd)/..
export PATH=$(echo "$PATH:$AFLNET" | tr ':' '\n' | grep -v '^\.$' | paste -sd':')
export AFL_PATH=$AFLNET