#!/bin/sh -x

if [ -z "$1" ]; then
  echo "No shard specified. Aborting."
  exit 1
fi

Shard=$1; shift

if [ -z "${AL_ROOT}" ]; then
  echo "NO AL_ROOT found in environment. Aborting."
  exit 1
fi

${AL_ROOT}/pkg/assemblyline/al/run/run_resubmit.py -s ${Shard}
${AL_ROOT}/pkg/assemblyline/al/run/run_dispatcher.py -s ${Shard} &

Pid=$!

rotate() {
	kill -INT ${Pid}
	exit 0
}

trap rotate INT

wait ${Pid}

