# AutoReconR

AutoReconR attempts to automate parts of the network reconnaissance and service enumeration phase. Respective findings are described and summarized in an automatically generated report. As such, AutoReconR may facilitate identifying potential weaknesses in target systems more quickly and finding an entry point. 

The tool is intended to be running in the background while the tester can focus on other tasks in parallel. For instance, in laboratory environments as offered by Offensive Security or during security exams like OSCP, the tester may start writing exploits while AutoReconR scans the remaining targets and performs automatic service enumeration. 

The tool is highly customizable and supports different scanning profiles in order to efficiently balance program runtime with the amount of extracted information. It should be noted though that the scanning approach is generally deep and aims at examining a system in great detail. A typical program run may take between 20 and 60 minutes, depending on the discovered system services and corresponding programs that should be subsequently executed. Applications such as enum4linux, gobuster, or nikto are able to retrieve extensive information about a target but also increase the required total scanning time. 

It is also noteworthy that AutoReconR **does not perform any automatic exploitation**, although respective programs can be easily integrated and triggered with the help of custom configuration files that will be automatically included at startup. 

## Origin and Features

AutoReconR is forked from [AutoRecon](https://github.com/Tib3rius/AutoRecon) by Tib3rius. The tool was extended with a number of additional features, including

* the possibility to specify targets either via the command line or an input file,
* define scanning and service enumeration profiles in custom configuration files,
* automatically store scanning results in a folder structure categorized by service name,
* trigger additional actions based on identified services and service patterns,
* balance program runtime and scanning depth with the help of complexity levels, and
* summarize findings in a corresponding (at the moment - very basic) PDF report.

## Requirements

* Python 3
* enscript (to be replaced later)
* colorama
* toml

Once Python 3 and enscript (`sudo apt-get install enscript`) are installed, pip3 can be used to install the other requirements:

```bash
$ pip3 install -r requirements.txt
```

In addition it is advised downloading word lists for password brute forcing and web crawling from the SecLists project (https://github.com/danielmiessler/SecLists).

On Kali Linux, these files are stored in the /usr/share/seclists/ directory or can be installed by running:

```bash
$ sudo apt-get install seclists
```

## Options and Usage


```
usage: autoreconr.py [-h] [-ct <number>] [-cs <number>]
                     [--config-dir CONFIG_DIR] [--profile PROFILE] [-o OUTPUT]
                     [--nmap NMAP | --nmap-append NMAP_APPEND]
                     [--skip-service-scan] [--skip-post-processing]
                     [--run-level RUN_LEVEL [RUN_LEVEL ...]] [--run-only]
                     [-r TARGET_FILE] [--no-report] [-v]
                     [--heartbeat HEARTBEAT] [--disable-sanity-checks]
                     [targets [targets ...]]

Network reconnaissance tool for automatically discovering and enumerating
services on a target.

positional arguments:
  targets               IP addresses (e.g. 10.0.0.1), CIDR notation (e.g.
                        10.0.0.1/24), or resolvable hostnames (e.g. foo.bar)
                        to scan.

optional arguments:
  -h, --help            show this help message and exit
  -ct <number>, --concurrent-targets <number>
                        The maximum number of target hosts to scan
                        concurrently. Default: 5
  -cs <number>, --concurrent-scans <number>
                        The maximum number of scans to perform per target
                        host. Default: 20
  --config-dir CONFIG_DIR
                        The path to the configuration directory.
  --profile PROFILE     The port scanning profile to use (defined in port-
                        scan-profiles.toml). Default: default
  -o OUTPUT, --output OUTPUT
                        The output directory for results. Default: results
  --nmap NMAP           Override the {nmap_extra} variable in scans. Default:
                        --reason -Pn
  --nmap-append NMAP_APPEND
                        Append to the default {nmap_extra} variable in scans.
  --skip-service-scan   Do not perfom extended service scanning but only
                        document commands.
  --skip-post-processing
                        Do not run any post-processing modules when specific
                        service patterns are discovered.
  --run-level RUN_LEVEL [RUN_LEVEL ...]
                        During extended service scanning, only run scanners of
                        a certain complexity level or below.
  --run-only            If enabled, only run scanners of the specified
                        complexity level during extended service scanning.
  -r TARGET_FILE, --read TARGET_FILE
                        Read targets from file.
  --no-report           Do not create a summary report after completing
                        scanning a target.
  -v, --verbose         Enable verbose output. Repeat for more verbosity.
  --heartbeat HEARTBEAT
                        Specifies the heartbeat interval for notification
                        messages during scanning.
  --disable-sanity-checks
                        Disable sanity checks that would otherwise prevent the
                        scans from running.
```

Assuming the list of targets has been defined in the file *ips.txt*, the scanning process can be easily started with:

```bash
$ pyton3 autoreconr -r ips.txt
```

In the case above, autoreconr is invoked with the `default` profile. This profile includes a standard TCP nmap scan (for the most common 1,000 ports), a full TCP scan, and a UDP scan for the top 20 ports. For any service that is discovered, in-depth service enumeration is performed, based on the applications that are listed in the  `service-scans` profile.

If, e.g., a running web server is identified on a target, autoreconr automatically launches *curl*, *whatweb*, *gobuster*, and *nikto* in order to fingerprint the service and potentially discover sensitive files and directories. Autoreconr also creates a screenshot of any resource that is found.

Please note that the runtime of especially gobuster and nikto can be lengthy, depending on the complexity of the service and the corresponding web application.

In order to efficiently balance the runtime of the program and the scanning depth, autoreconr offers a number of different command line options, including skipping service enumeration entirely or limiting it to certain ports or applications. On the other hand, for a particular intense scan, autoreconr can automatically trigger additional commands when a match with a pre-defined pattern is found. Thereby, it is for instance possible starting another *gobuster* search for any directory that is discovered and even enumerating applications on a deeper hierarchy level in more detail. A *heartbeat* routine is called in parallel to inform the user of the number of remaining tasks in order to roughly estimate the runtime of the entire scan.

