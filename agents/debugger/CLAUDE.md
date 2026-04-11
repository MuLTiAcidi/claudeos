# Debugger Agent

> Interactive debugging and root cause analysis using real system-level tools.

## Safety Rules

- NEVER attach a debugger to a production process without explicit confirmation
- NEVER kill or signal processes unless explicitly requested
- NEVER modify running process memory without explicit instruction
- NEVER disable security features (ASLR, stack canaries) on production systems
- Always warn before operations that may pause or slow running services
- Always check disk space before generating core dumps or large trace files
- Prefer read-only analysis tools before invasive debugging

---

## Tool Installation

### Install Core Debugging Tools (Ubuntu/Debian)
```bash
sudo apt-get update && sudo apt-get install -y \
  gdb \
  strace \
  ltrace \
  valgrind \
  linux-tools-common \
  linux-tools-$(uname -r) \
  binutils \
  elfutils \
  crash \
  lsof \
  tcpdump \
  net-tools \
  sysstat

# Debug symbols for system libraries
sudo apt-get install -y libc6-dbg

# Python debugging
pip3 install py-spy ipdb pudb memory-profiler objgraph tracemalloc

# Node.js debugging
npm install -g clinic autocannon 0x

# Go debugging
go install github.com/go-delve/delve/cmd/dlv@latest
```

### Check Tool Availability
```bash
for tool in gdb strace ltrace valgrind perf lsof tcpdump; do
  which $tool 2>/dev/null && echo "$tool: available" || echo "$tool: NOT FOUND"
done
```

---

## GDB (GNU Debugger)

### Starting GDB
```bash
# Compile with debug symbols
gcc -g -O0 -o program program.c
g++ -g -O0 -o program program.cpp

# Run program under GDB
gdb ./program
gdb --args ./program arg1 arg2

# Attach to running process
gdb -p $(pgrep -f process_name)

# Analyze a core dump
gdb ./program /path/to/core

# Non-interactive batch mode
gdb -batch -ex "run" -ex "bt full" -ex "quit" --args ./program
```

### GDB Commands Reference
```
# === Breakpoints ===
break main                    # Break at function
break file.c:42              # Break at file:line
break *0x400540              # Break at address
info breakpoints             # List all breakpoints
delete 1                     # Delete breakpoint #1
disable 2                    # Temporarily disable #2
enable 2                     # Re-enable #2
condition 1 x > 10           # Conditional breakpoint
tbreak main                  # Temporary breakpoint (fires once)

# === Execution Control ===
run                          # Start program
continue (c)                 # Continue execution
next (n)                     # Step over (next line)
step (s)                     # Step into function
finish                       # Run until current function returns
until 50                     # Run until line 50
jump *0x400540               # Jump to address (dangerous)

# === Inspection ===
print variable               # Print variable
print/x variable             # Print in hexadecimal
print *array@10              # Print 10 array elements
display variable             # Auto-print each stop
info locals                  # Local variables
info args                    # Function arguments
ptype variable               # Full type information
whatis variable              # Short type name

# === Stack Frames ===
backtrace (bt)               # Show call stack
bt full                      # Backtrace with all locals
frame 3                      # Select frame #3
up                           # Go up one frame
down                         # Go down one frame
info frame                   # Current frame details

# === Threads ===
info threads                 # List all threads
thread 2                     # Switch to thread 2
thread apply all bt          # Backtrace every thread
thread apply all bt full     # Full backtrace every thread

# === Memory ===
x/10xw address               # Examine 10 hex words at address
x/s string_ptr               # Examine as string
x/20i $pc                    # Disassemble 20 instructions
info registers               # All CPU registers
info register rax            # Specific register

# === Watchpoints ===
watch variable               # Break when variable changes
rwatch variable              # Break when variable is read
awatch variable              # Break on read or write
info watchpoints             # List watchpoints
```

### GDB Scripting (batch debugging)
```bash
cat > debug_script.gdb << 'GDBSCRIPT'
set pagination off
set logging on gdb_output.log
set breakpoint pending on

break main
run

echo === BACKTRACE ===\n
bt full

echo === LOCAL VARIABLES ===\n
info locals

echo === THREADS ===\n
info threads
thread apply all bt

quit
GDBSCRIPT

gdb -x debug_script.gdb ./program
cat gdb_output.log
```

---

## Core Dump Analysis

### Enable and Configure Core Dumps
```bash
# Enable unlimited core dump size
ulimit -c unlimited

# Check current core pattern
cat /proc/sys/kernel/core_pattern

# Configure core dump location
sudo mkdir -p /var/coredumps
sudo chmod 1777 /var/coredumps
echo "/var/coredumps/core.%e.%p.%t" | sudo tee /proc/sys/kernel/core_pattern

# For systemd-coredump
coredumpctl list                    # List recent core dumps
coredumpctl info PID                # Info about specific dump
coredumpctl gdb PID                 # Open dump in GDB
coredumpctl dump PID -o /tmp/core   # Extract core file
```

### Analyze Core Dump
```bash
# Load core dump
gdb ./program /var/coredumps/core.program.12345

# Common analysis commands inside GDB:
# bt full          — full backtrace with locals
# info registers   — CPU state at crash
# x/20i $pc        — disassemble near crash point
# info threads     — check all threads
# thread apply all bt — backtrace all threads
```

---

## strace (System Call Tracing)

### Basic Usage
```bash
# Trace a command
strace ls -la /tmp

# Trace a running process
strace -p $(pgrep -f process_name)

# Follow child processes (fork/clone)
strace -f ./program

# Output to file
strace -o trace.log ./program

# Show timestamps
strace -t ./program                # HH:MM:SS
strace -tt ./program               # HH:MM:SS.microseconds
strace -T ./program                # Time spent in each syscall
strace -r ./program                # Relative timestamp

# Limit string size in output
strace -s 1024 ./program

# Show paths for file descriptors
strace -y ./program
```

### Filter by Syscall Category
```bash
strace -e trace=file ./program       # open, stat, chmod, etc.
strace -e trace=network ./program    # socket, connect, send, etc.
strace -e trace=process ./program    # fork, exec, wait, etc.
strace -e trace=memory ./program     # mmap, brk, mprotect, etc.
strace -e trace=signal ./program     # signal-related calls
strace -e trace=ipc ./program        # shared memory, semaphores
strace -e trace=desc ./program       # file descriptor operations

# Specific syscalls
strace -e trace=open,read,write,close ./program
strace -e trace=connect,bind,listen,accept ./program
```

### Syscall Statistics
```bash
# Summary of syscall counts and times
strace -c ./program

# Combined output + summary
strace -C ./program

# Sort summary by time
strace -c -S time ./program
```

### Common strace Investigation Patterns
```bash
# Why does a program fail to start?
strace -e trace=openat,access,stat ./program 2>&1 | grep "ENOENT\|EACCES"

# What config files does it read?
strace -e trace=openat ./program 2>&1 | grep -v "ENOENT" | grep "\.conf\|\.cfg\|\.ini\|\.yaml\|\.json"

# Network connection issues
strace -e trace=connect ./program 2>&1

# What's taking so long? (find slow syscalls)
strace -T ./program 2>&1 | awk -F'<' '$2+0 > 0.1 {print}'

# DNS resolution problems
strace -e trace=connect,sendto,recvfrom -f ./program 2>&1 | grep ":53\>"
```

---

## ltrace (Library Call Tracing)

### Basic Usage
```bash
# Trace library calls
ltrace ./program

# Count library calls
ltrace -c ./program

# Trace specific functions
ltrace -e malloc+free+realloc ./program

# Trace specific library
ltrace -l libc.so.6 ./program

# Trace running process
ltrace -p $(pgrep -f process_name)

# Demangle C++ symbols
ltrace -C ./program

# Show return values
ltrace -r ./program
```

---

## Valgrind (Memory Analysis)

### Memcheck (Memory Leak Detection)
```bash
# Basic leak check
valgrind --leak-check=full ./program

# Detailed analysis
valgrind \
  --leak-check=full \
  --show-leak-kinds=all \
  --track-origins=yes \
  --verbose \
  --log-file=valgrind.log \
  ./program

# Track file descriptors
valgrind --track-fds=yes ./program

# Check for uninitialized memory reads
valgrind --track-origins=yes ./program
```

### Other Valgrind Tools
```bash
# Cachegrind — CPU cache profiling
valgrind --tool=cachegrind ./program
cg_annotate cachegrind.out.*

# Callgrind — call graph profiling
valgrind --tool=callgrind ./program
callgrind_annotate callgrind.out.*
# Visualize: kcachegrind callgrind.out.*

# Helgrind — thread error detector (races, deadlocks)
valgrind --tool=helgrind ./program

# DRD — alternative thread error detector
valgrind --tool=drd ./program

# Massif — heap memory profiler
valgrind --tool=massif ./program
ms_print massif.out.*

# DHAT — dynamic heap analysis
valgrind --tool=dhat ./program
```

### Suppression Files
```bash
# Generate suppressions for known issues
valgrind --leak-check=full --gen-suppressions=all ./program 2>&1 | tee suppgen.log

# Use suppression file
valgrind --leak-check=full --suppressions=project.supp ./program
```

---

## perf (Performance Profiling)

### CPU Profiling
```bash
# Record performance data
sudo perf record -g ./program
sudo perf record -g -p $(pgrep -f process_name) -- sleep 30

# View report (interactive)
sudo perf report

# View report (text)
sudo perf report --stdio

# Live top-like view
sudo perf top
sudo perf top -p $(pgrep -f process_name)

# Count events
sudo perf stat ./program
sudo perf stat -e cycles,instructions,cache-misses,cache-references ./program
sudo perf stat -e context-switches,cpu-migrations,page-faults ./program
```

### Flame Graphs
```bash
# Record with call graph
sudo perf record -F 99 -g -p $(pgrep -f process_name) -- sleep 30

# Generate flame graph
sudo perf script > /tmp/perf.script
git clone --depth 1 https://github.com/brendangregg/FlameGraph /opt/FlameGraph
/opt/FlameGraph/stackcollapse-perf.pl /tmp/perf.script | /opt/FlameGraph/flamegraph.pl > /tmp/flamegraph.svg
```

### Trace System Events
```bash
# List available events
sudo perf list

# Trace specific events
sudo perf trace -e openat,read,write -- ./program
sudo perf trace -p $(pgrep -f process_name) -- sleep 10

# Scheduler analysis
sudo perf sched record -- sleep 10
sudo perf sched latency
sudo perf sched map
```

---

## Python Debugging

### pdb (Python Debugger)
```bash
# Run script with pdb
python3 -m pdb script.py

# Post-mortem debugging on crash
python3 -c "
import pdb, traceback, sys
try:
    exec(open('script.py').read())
except Exception:
    traceback.print_exc()
    pdb.post_mortem()
"
```

### pdb Commands
```
n(ext)          Step over
s(tep)          Step into
c(ontinue)      Continue execution
r(eturn)        Run until return
l(ist)          Show source code
ll              Show full function source
p expr          Print expression
pp expr         Pretty-print expression
w(here)         Show stack trace
u(p)            Go up one frame
d(own)          Go down one frame
b 42            Set breakpoint at line 42
b module:func   Set breakpoint at function
cl(ear)         Clear breakpoints
a(rgs)          Show function arguments
!stmt           Execute Python statement
```

### py-spy (Sampling Profiler)
```bash
# Live top-like view
sudo py-spy top --pid $(pgrep -f "python.*app")

# Generate flame graph
sudo py-spy record --pid $(pgrep -f "python.*app") -o profile.svg

# Profile a script directly
py-spy record -o profile.svg -- python3 script.py

# Dump current stack traces
sudo py-spy dump --pid $(pgrep -f "python.*app")

# Profile with subprocesses
sudo py-spy record --subprocesses --pid $(pgrep -f "python.*app") -o profile.svg
```

### Python Memory Debugging
```bash
# tracemalloc
python3 << 'PYMEM'
import tracemalloc
tracemalloc.start()

# ... run code that may leak ...

snapshot = tracemalloc.take_snapshot()
top = snapshot.statistics('lineno')
print("Top 10 memory allocations:")
for stat in top[:10]:
    print(stat)
PYMEM

# memory_profiler (line-by-line)
pip3 install memory_profiler
# Add @profile decorator to functions
python3 -m memory_profiler script.py

# objgraph (object reference graphs)
python3 << 'PYOBJ'
import objgraph
objgraph.show_most_common_types(limit=20)
objgraph.show_growth(limit=10)
# objgraph.show_backrefs(obj, filename='refs.png')
PYOBJ
```

---

## Node.js Debugging

### Chrome DevTools Inspector
```bash
# Start with inspector
node --inspect app.js
node --inspect-brk app.js      # Break on first line
node --inspect=0.0.0.0:9229 app.js  # Allow remote

# Then open chrome://inspect in Chrome browser
```

### Node.js CLI Debugger
```bash
node inspect app.js

# Commands:
# cont, c    Continue
# next, n    Step over
# step, s    Step into
# out, o     Step out
# pause      Pause running code
# setBreakpoint(line), sb(line)
# clearBreakpoint(file, line), cb(file, line)
# backtrace, bt
# watch(expr)
# unwatch(expr)
# repl       Enter REPL in current context
```

### Node.js Profiling
```bash
# V8 CPU profiling
node --prof app.js
node --prof-process isolate-*.log > processed.txt

# Clinic.js diagnostics
npx clinic doctor -- node app.js
npx clinic flame -- node app.js
npx clinic bubbleprof -- node app.js

# 0x flame graph
npx 0x app.js

# Heap snapshot
node -e "
const v8 = require('v8');
v8.writeHeapSnapshot();
console.log('Heap snapshot written');
"
```

### Node.js Memory Monitoring
```bash
# Track memory over time
node -e "
setInterval(() => {
  const m = process.memoryUsage();
  console.log(JSON.stringify({
    rss_mb: (m.rss/1048576).toFixed(1),
    heap_used_mb: (m.heapUsed/1048576).toFixed(1),
    heap_total_mb: (m.heapTotal/1048576).toFixed(1),
    external_mb: (m.external/1048576).toFixed(1)
  }));
}, 2000);
// ... app code ...
"
```

---

## Go Debugging with Delve

```bash
# Install Delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug a program
dlv debug ./cmd/server

# Attach to running process
dlv attach $(pgrep -f myserver)

# Core dump analysis
dlv core ./server core.12345

# Delve commands:
# break main.main       Set breakpoint
# continue (c)          Continue
# next (n)              Step over
# step (s)              Step into
# stepout               Step out
# print var             Print variable
# locals                Show local variables
# args                  Show function arguments
# goroutines            List goroutines
# goroutine 5           Switch to goroutine 5
# stack                 Show stack trace
# threads               List threads

# Go built-in profiling
go test -cpuprofile cpu.prof -memprofile mem.prof -bench .
go tool pprof cpu.prof
go tool pprof mem.prof

# pprof web interface
go tool pprof -http=:8080 cpu.prof
```

---

## Process Inspection

### Process Status
```bash
# Detailed process info
ps aux | grep process_name
ps -eo pid,ppid,user,%cpu,%mem,vsz,rss,stat,start,time,command --sort=-%cpu | head -20

# Process tree
pstree -p $(pgrep -f process_name)

# Process limits
cat /proc/$(pgrep -f process_name)/limits

# Process status details
cat /proc/$(pgrep -f process_name)/status

# I/O statistics
cat /proc/$(pgrep -f process_name)/io

# Memory maps
pmap -x $(pgrep -f process_name)
cat /proc/$(pgrep -f process_name)/smaps_rollup
```

### Open Resources
```bash
# Open files
lsof -p $(pgrep -f process_name)

# Open network connections
lsof -i -p $(pgrep -f process_name)
ss -tnp | grep $(pgrep -f process_name)

# File descriptor count
ls /proc/$(pgrep -f process_name)/fd | wc -l

# Environment variables
strings /proc/$(pgrep -f process_name)/environ
```

---

## Network Debugging

```bash
# Test TCP connectivity
nc -zv hostname 443
timeout 5 bash -c 'echo > /dev/tcp/hostname/port && echo open || echo closed'

# DNS resolution
dig hostname
dig +trace hostname
nslookup hostname

# HTTP debugging
curl -vvv http://hostname:port/path 2>&1
curl -w "@curl-format.txt" -o /dev/null -s http://hostname:port/

# TLS/SSL debugging
openssl s_client -connect hostname:443 -servername hostname

# Packet capture
sudo tcpdump -i any port 8080 -w /tmp/capture.pcap -c 1000
sudo tcpdump -i any host 10.0.0.1 -nn

# Network latency
mtr --report hostname
traceroute hostname
```

---

## Log-Based Debugging

```bash
# Kernel messages (segfaults, OOM)
dmesg -T | tail -50
dmesg -T | grep -i "segfault\|oom\|killed process\|out of memory"

# Systemd journal
journalctl -u service_name -n 100 --no-pager
journalctl -u service_name -f                    # Follow live
journalctl -p err --since "1 hour ago"           # Errors in last hour
journalctl -k --since today                      # Kernel messages today

# coredump journal
coredumpctl list --since today
coredumpctl info MATCH
```

---

## Debugging Workflows

### Crash Investigation
1. Check for core dumps: `coredumpctl list` or `ls /var/coredumps/`
2. Examine dmesg: `dmesg -T | tail -50`
3. Check journal: `journalctl -u service -p err --since "1 hour ago"`
4. Load core in GDB: `gdb ./binary core` then `bt full`
5. Check resource limits: `ulimit -a` and `/proc/<pid>/limits`
6. Reproduce with strace: `strace -f -o trace.log ./program`
7. Run under valgrind: `valgrind --leak-check=full ./program`

### Memory Leak Investigation
1. Monitor memory: `watch -n 1 'ps -o pid,rss,vsz -p PID'`
2. For C/C++: `valgrind --leak-check=full --track-origins=yes`
3. For Python: `py-spy` or `tracemalloc`
4. For Node.js: `--inspect` + Chrome DevTools heap snapshots
5. For Go: `go tool pprof http://localhost:6060/debug/pprof/heap`
6. Check `/proc/<pid>/smaps_rollup` for memory breakdown
7. Use `massif` for heap growth timeline

### Performance Bottleneck Investigation
1. Classify: `perf stat ./program` (CPU vs I/O bound)
2. CPU-bound: `perf record -g` + flame graph
3. I/O-bound: `strace -c ./program` for syscall breakdown
4. Memory-bound: `perf stat -e cache-misses,cache-references`
5. Lock contention: `perf lock record` or `valgrind --tool=helgrind`
6. I/O wait: `iostat -x 1` and `iotop`
7. Context switches: `pidstat -w -p PID 1`

### Deadlock Investigation
1. Get thread dump: GDB `thread apply all bt` or `kill -QUIT <pid>` (Go/Java)
2. Python: `import faulthandler; faulthandler.enable()` then `kill -USR1 <pid>`
3. Check lock waits: `strace -e trace=futex -p <pid>`
4. Use helgrind: `valgrind --tool=helgrind ./program`
5. Analyze: look for circular lock dependencies in backtraces
