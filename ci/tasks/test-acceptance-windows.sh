#!/bin/bash -eux

set -o pipefail

ROOT_DIR=$PWD
BBL_STATE_DIR=$ROOT_DIR/bbl-state

export PATH=$BBL_STATE_DIR/bin:$PATH
source $BBL_STATE_DIR/bosh.sh

bosh -n upload-stemcell $ROOT_DIR/bosh-candidate-stemcell-windows/*.tgz

export BOSH_DEPLOYMENT=bosh-dns-windows-acceptance

bosh -n deploy $ROOT_DIR/dns-release/ci/assets/windows-acceptance-manifest.yml \
    -v dns_release_path=$ROOT_DIR/dns-release

bosh run-errand acceptance-tests-windows
