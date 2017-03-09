

# command-line options: a list of (args, kwargs) tuples to add_argument
options = [
    (["hostlist"],
    {"help"     : "the list of hosts to scan" }),
    (["--thread-num", "-n"],
    {"help"     : "number of worker threads",
    "metavar"   : "N",
    "dest"      : "THREAD_NUM",
    "type"      : int,
    "default"   : 200 }),
    ([ "--db-filename", "-db" ],
    {"help"     : "the sqlite3 database file to use",
    "nargs"     : 1,
    "metavar"   : "DB",
    "dest"      : "DB_FILENAME",
    "default"   : "data/results.db"}),
    ([ "--print-freq", "-f" ],
    {"help"     : "progress report frequency",
    "metavar"   : "FREQ",
    "dest"      : "PRINT_FREQ",
    "type"      : int,
    "default"   : 10}),
    ([ "-q" ],
    {"help"     : "internal queue size",
    "metavar"   : "Q_SIZE",
    "dest"      : "MAX_Q_SIZE",
    "type"      : int,
    "default"   : 20}),
    ([ "--suspend-to" ],
    {"help"     : "where to dump program state when suspending",
    "metavar"   : "STATE_FILE",
    "dest"      : "SUSP_FILENAME",
	"default"	: "data/progstate.dump"}),
    ([ "--resume-from" ],
    {"help"     : "load state from this file and continue scanning",
    "metavar"   : "STATE_FILE",
    "dest"      : "STATE_FILE"}),
    ([ "--repeat" ],
    {"help"     : "scan continuously",
    "action"    : "store_true",
	"dest"		: "REPEAT",
    "default"   : False}),
    ([ "--with-delay" ],
    {"help"     : "set delay between repeated scans, in seconds; "
                  "this implies --repeat",
    "metavar"   : "REPEAT_DELAY",
    "dest"      : "REPEAT_DELAY",
    "type"      : int,
    "default"   : 0}),
]
