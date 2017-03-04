# scanner

This is a small, threaded, SSL/TLS scanner, done in Python 3. It is a work in
progress.

The `SSLTester` module contains the `SSLTester` class that does the actual
scanning. It currently checks the supported SSL/TLS versions and cipher suites
on port 443. It is also currently limited to those protocols and ciphers
provided in the Python `ssl` module.

`main.py` is the main script; it loads in the input file, spins up SSLTester
threads, feeds them the list of target hosts, and receives the results. It also
takes care of things like user interaction, suspending/resuming the scan,
database initialization, etc.

The input file consists of one (hostname, IPv4 address) pair per line. An
example is provided in `data/example_input`. The `lookup.py` script can be used
to do parallel reverse-DNS lookup. If it cannot find the hostname, it sets it
to "?" instead. 

The `data` folder contains the input example, and is the default output
location.

### How to use
Run as
```bash
./main.py data/example_wp_list
```
It should output results to `data/results.db`. Add the `--repeat` option for
continuous scanning. You can then stop it with a KeyboardInterrupt (Ctrl+C).

To suspend it (and dump its state to disk), just press Ctrl+C twice.
To continue where it left of, start it as
```bash
./main.py hostlist --resume-from state_dump
```
where `state_dump` is the file containing the state. By default, the state is
dumped to `data/progstate.dump`.

For a list of all options, run without arguments, or see `options.py`.
