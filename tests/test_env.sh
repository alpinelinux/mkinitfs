# shellcheck shell=sh

atf_srcdir="$(atf_get_srcdir)"
srcdir="$atf_srcdir/.."
PATH="$srcdir:$PWD/bin:$PATH"

export ROOT="$PWD"
export MOCK=echo
export KOPT_bootstrap_usr_merged="yes"

init_tests() {
	TESTS=
	for t; do
		TESTS="$TESTS $t"
		atf_test_case "$t"
	done
	export TESTS
}

atf_init_test_cases() {
	for t in $TESTS; do
		atf_add_test_case "$t"
	done
}
