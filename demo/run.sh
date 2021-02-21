#!/bin/bash

file="${1}"
shift
tsc -t es5 "${file}" && node "${file%.ts}.js" "${@}"
