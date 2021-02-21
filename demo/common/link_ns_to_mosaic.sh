#!/bin/bash

id="${1}"
ns="${2}"
symbol-cli transaction mosaicalias --profile service --action Link --mosaic-id "${id}" --namespace-name "${ns}"