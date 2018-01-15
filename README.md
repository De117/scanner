# scanner

This is a small, threaded SSL/TLS scanner, written in Python 3, meant for
scanning web-servers. It currently records supported SSL/TLS versions,
cipher suites, TLS extensions, the certificate chain, and a few
potentially relevant HTTP headers.


## Structure
`main.py` is the main script; it loads in the input file, spins up
SSLTester threads, feeds them the list of target hosts, and receives the
results. It also takes care of things like user interaction, suspending/resuming
the scan, database initialization, etc.

The `SSLTester` module contains the actual scanning code. It used to use
the `ssl` module; now it makes and parses the TLS handshake manually.

The `lookup.py` script is not strictly part of the scanner, but here for
convenience. It does reverse-DNS lookup.

The `data` folder contains the input example, and is the default output
location.


## How to use
Run as
```bash
./main.py data/example_wp_list
```
It should output results to `data/results.db`. Add the `--repeat` option for
continuous scanning. You cancel the repetition with a KeyboardInterrupt (Ctrl+C).

To suspend it (and dump its state to disk), just press Ctrl+C twice.

To continue where it left of, start it as
```bash
./main.py hostlist --resume-from state_dump
```
where `state_dump` is the file containing the state. By default, the state is
dumped to `data/progstate.dump`.

It tries to be informative.
For a list of all options, run without arguments, or see `options.py`.
