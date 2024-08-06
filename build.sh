#!/bin/bash

SCRIPT_DIR="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")"

VERSION="$(<$SCRIPT_DIR/VERSION)"
TOOL="docker"
IMAGE="tasp/libkrb5:$VERSION"

while getopts "t:" opt
do
    case $opt in
        t) TOOL=${OPTARG};;
    esac
done

cd $SCRIPT_DIR
if [[ "$($TOOL images -q $IMAGE 2> /dev/null)" != "" ]]; then
    $TOOL image rmi -f $IMAGE
fi

$TOOL build -t $IMAGE --no-cache .
$TOOL image prune -f --filter label=stage=builder
