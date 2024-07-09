#!/bin/sh

go tool nm "$1" > tags.txt

count=$(grep -c '_Cfunc_go_openssl' tags.txt)

if [ "$count" -eq 0 ]; then
    echo "Error: Symbol '_Cfunc_go_openssl' not found in binary."
    exit 1
else
    echo "Success: Symbol '_Cfunc_go_openssl' found $count times in binary."
fi