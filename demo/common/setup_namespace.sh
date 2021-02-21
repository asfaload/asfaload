#!/bin/bash

[[ "${#}" -eq 1 ]] || { echo "pass namespace as argument" ; exit 1; }

ns=$1

symbol-cli transaction namespace --profile service --name $ns --rootnamespace --duration 172800
