#!/bin/bash

test_dir=$(dirname $(readlink -f "${BASH_SOURCE[0]}"))
root_dir=$(readlink -f ${test_dir}/..)
PYTHON=python3



test_ssi()
{
    # test ssi
    echo "=============FR SSI ==================="
    ${PYTHON} ${root_dir}/rss.py -v -n 3
    ${PYTHON} ${root_dir}/rss.py -v -n 3
}
test_nist()
{
    echo "=============NIST ==================="
    ${PYTHON} ${root_dir}/rss.py -v --nist -n 3
    ${PYTHON} ${root_dir}/rss.py -v --nist -D $(date +%Y) | head -n3
    ${PYTHON} ${root_dir}/rss.py -v --nist -q -D $(date +%Y) -s critical
    ${PYTHON} ${root_dir}/rss.py -v --nist -b 2016--2018 -s critical -n 7
    ${PYTHON} ${root_dir}/rss.py -v --nist -i CVE-2025-25022
    ${PYTHON} ${root_dir}/rss.py -v --nist -k Linux -b 2016--2025

}
test_cve()
{
    echo "=============CVE.ORG ==================="
    ${PYTHON} ${root_dir}/rss.py --get-cve-org-data
    ${PYTHON} ${root_dir}/rss.py --cve-org -f ./cvelistV5-main.zip -v -n 3
    ${PYTHON} ${root_dir}/rss.py --cve-org -f ./cvelistV5-main.zip -v -D $(date +%Y)
    ${PYTHON} ${root_dir}/rss.py --cve-org -f ./cvelistV5-main.zip -v -D $(date +%Y) -s critical
    ${PYTHON} ${root_dir}/rss.py --cve-org -f ./cvelistV5-main.zip -v -k Linux -b 2016--2025
}

args=$1

tmpdir=$(mktemp -d)
cd $tmpdir

case ${args,,} in
    "ssi")
        test_ssi
    ;;

    "nist")
        test_nist
    ;;

    "cve")
        test_cve
    ;;

    *)
        test_ssi
        test_nist
        test_cve
    ;;
esac

#end test
rm -rf ${tmpdir}

cd -