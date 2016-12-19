#!/bin/bash -e

if [[ $# -ne 3 ]]; then
  echo >&2 "Usage: $0 <asn1file> <typename> <xerfile>"
  exit 1
fi

asn1file=$(readlink -f $1)
typename=$2
xerfile=$(readlink -f $3)

workdir=$(mktemp -d)
trap "rm -rf ${workdir}" EXIT

cd ${workdir}
(
  asn1c ${asn1file}
  CFLAGS="-DPDU=${typename}" make TARGET=converter -f Makefile.am.sample
) >&2
./converter -ixer -oder ${xerfile}
