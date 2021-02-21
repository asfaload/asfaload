#!/bin/bash

[[ "${#}" -eq 2 ]] || { echo "pass parent and subnamespace as argument" ; exit 1; }

ns=$1
subns=$2

symbol-cli transaction namespace --profile service --subnamespace --parent-name $ns --name $subns
