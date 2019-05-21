#!/usr/bin/env python3
#
#    AutoReconR attempts to automate parts of the network reconnaissance process and creates a respective findings report.
#
#    This program can be redistributed and/or modified under the terms of the
#    GNU General Public License, either version 3 of the License, or (at your
#    option) any later version.
#

import argparse
import os
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from lib import auxiliary, configuration, scanner

__version__ = '0.0.5'

nmap_default_options = '--reason -Pn'

CONFIG_ITEMS = {
                    'rootdir'               :   os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__))),
                    'configdir'             :   os.path.join(os.getcwd(), os.path.dirname(__file__), 'config', 'default'),
                    
                    'applications'          :   {},
                    'files'                 :   {},
                    
                    'port_scan_profiles'    :   {},
                    'service_scan_profiles' :   {},
                    'patterns'              :   [],

               }

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Network reconnaissance tool for automatically discovering and enumerating services on a target.', epilog = auxiliary.get_header(__version__))
    parser.add_argument('targets', action='store', help='IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g. foo.bar) to scan.', nargs="*")
    parser.add_argument('-ct', '--concurrent-targets', action='store', metavar='<number>', type=int, default=5, help='The maximum number of target hosts to scan concurrently. Default: %(default)s')
    parser.add_argument('-cs', '--concurrent-scans', action='store', metavar='<number>', type=int, default=20, help='The maximum number of scans to perform per target host. Default: %(default)s')
    parser.add_argument('--config-dir', action='store', default=CONFIG_ITEMS['configdir'],  help='The path to the configuration directory.')
    parser.add_argument('--profile', action='store', default='default', help='The port scanning profile to use (defined in port-scan-profiles.toml). Default: %(default)s')
    parser.add_argument('-o', '--output', action='store', default='results', help='The output directory for results. Default: %(default)s')
    nmap_group = parser.add_mutually_exclusive_group()
    nmap_group.add_argument('--nmap', action='store', default=nmap_default_options, help='Override the {nmap_extra} variable in scans. Default: %(default)s')
    nmap_group.add_argument('--nmap-append', action='store', default='', help='Append to the default {nmap_extra} variable in scans.')
    parser.add_argument('--skip-service-scan', action='store_true', default=False, help='Do not perfom extended service scanning but only document commands.')
    parser.add_argument('--skip-post-processing', action='store_true', default=False, help='Do not run any post-processing modules when specific service patterns are discovered.')
    parser.add_argument('--run-level', action='store', type=int, default=[0], nargs="+", help='During extended service scanning, only run scanners of a certain complexity level or below.')
    parser.add_argument('--run-only', action='store_true', default=False, help='If enabled, only run scanners of the specified complexity level during extended service scanning.')
    parser.add_argument('-r', '--read', action='store', type=str, default='', dest='target_file', help='Read targets from file.')
    parser.add_argument('--no-report', action='store_true', default=False, help='Do not create a summary report after completing scanning a target.')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Enable verbose output. Repeat for more verbosity.')
    parser.add_argument('--heartbeat', action='store', type=int, default=180, help='Specifies the heartbeat interval for notification messages during scanning.')
    parser.add_argument('--disable-sanity-checks', action='store_true', default=False, help='Disable sanity checks that would otherwise prevent the scans from running.')
    parser.error = lambda s: auxiliary.fail(s[0].upper() + s[1:])
    args = parser.parse_args()
    
    if os.path.exists(args.config_dir):
        CONFIG_ITEMS['configdir'] = args.config_dir
    else:
        auxiliary.fail('The configuration directory {configuration.configdir} was not found.') 

    config = configuration.get_configuration(CONFIG_ITEMS)
    errors, targets = configuration.check_configuration(config, args)    
    if errors: sys.exit(1)

    start_timer = auxiliary.get_time()
    with ProcessPoolExecutor(max_workers=args.concurrent_targets) as executor:
        futures = []

        for address in targets:
            target = scanner.Target(address, config)
            futures.append(executor.submit(scanner.scan_host, target, args))

        try:
            for future in as_completed(futures):
                future.result()
        except KeyboardInterrupt:
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False)
            sys.exit(1)
    end_timer = auxiliary.get_time()
    tdelta = auxiliary.get_time(time = end_timer, delta = True) - auxiliary.get_time(time = start_timer, delta = True)
    print('\nScanning completed in {}.'.format(tdelta))

