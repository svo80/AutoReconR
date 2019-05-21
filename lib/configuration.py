#!/usr/bin/env python3

import os
import glob
import toml
from lib import auxiliary, targetlist

# defines how sections in configuration files should be mapped to internally
markup =        { 
                    'applications'      :   ('applications', {}),
                    'files'             :   ('files', {}),
                    'wordlists'         :   ('wordlists', {}),
                    'port-scan'         :   ('port_scan_profiles', {}),
                    'service-scan'      :   ('service_scan_profiles', {}),
                    'pattern'           :   ('patterns', [])
                }

global_values = {
                    'max_level'         :   3,
                }


def get_configuration(configuration):
    
    filenames = glob.glob(os.path.join(configuration['rootdir'], configuration['configdir'], '**', '*.toml'), recursive = True)
    for filename in filenames:
        try:
            with open(filename, 'r') as f:
                data = toml.load(f)

                for profile in data:
                    profile_name = profile.lower() 
                    if profile_name in markup.keys():
                        section_name = markup[profile_name][0]
                        if not section_name in configuration: configuration[section_name] = markup[profile_name][1]
                        
                        if isinstance(configuration[section_name], dict):
                            configuration[section_name] = {**configuration[section_name], **data[profile]}
                        elif isinstance(configuration[section_name], list):
                            configuration[section_name] += data[profile]
                        else:
                            auxiliary.warn('Warning: The section name {profile} in configuration file {filename} could not be mapped internally.')
                    else:
                        auxiliary.warn('Warning: Unknown markup {profile} discovered in configuration file {filename}.')
        except (OSError, toml.decoder.TomlDecodeError) as e:
            auxiliary.fail('Error: The configuration file {filename} could not be read.')


    if len(configuration['port_scan_profiles']) == 0:
        auxiliary.fail('There do not appear to be any port scan profiles configured in the {port_scan_profiles_config_file} config file.')

    configuration = {**configuration, **global_values}

    return configuration


def check_configuration(config, args):
    targets = []
    
    try:
        port_scan_profiles_config = config['port_scan_profiles'] 
        service_scans_config = config['service_scan_profiles']
        global_patterns = config['patterns']
        files = config['files']
        applications = auxiliary.objectview(config['applications'])
        wordslists = auxiliary.objectview(config['wordlists'])
    except (KeyError, AttributeError) as err: 
        auxiliary.fail('Error: A configuration section was not found or could not be successfully processed: {err}')

    errors = False

    if args.concurrent_targets <= 0:
        auxiliary.error('Argument -ch/--concurrent-targets: must be at least 1.')
        errors = True

    concurrent_scans = args.concurrent_scans

    if concurrent_scans <= 0:
        auxiliary.error('Argument -ct/--concurrent-scans: must be at least 1.')
        errors = True

    if min(args.run_level) < 0 or max(args.run_level) > config['max_level']:
        auxiliary.error('Argument --run-level: must be between 0 (default) and {}.'.format(config['max_level']))
        errors = True

    if args.heartbeat < 0 or args.heartbeat > 600:
        auxiliary.error('The heartbeat interval must be between 0 (off) and 600 seconds.')
        errors = True

    port_scan_profile = args.profile

    found_scan_profile = False
    for profile in port_scan_profiles_config:
        if profile == port_scan_profile:
            found_scan_profile = True
            for scan in port_scan_profiles_config[profile]:
                if 'service-detection' not in port_scan_profiles_config[profile][scan]:
                    auxiliary.error('The {profile}.{scan} scan does not have a defined service-detection section. Every scan must at least have a service-detection section defined with a command and a corresponding pattern that extracts the protocol (TCP/UDP), port, and service from the result.')
                    errors = True
                else:
                    if 'command' not in port_scan_profiles_config[profile][scan]['service-detection']:
                        auxiliary.error('The {profile}.{scan}.service-detection section does not have a command defined. Every service-detection section must have a command and a corresponding pattern that extracts the protocol (TCP/UDP), port, and service from the results.')
                        errors = True
                    else:
                        if '{ports}' in port_scan_profiles_config[profile][scan]['service-detection']['command'] and 'port-scan' not in port_scan_profiles_config[profile][scan]:
                            auxiliary.error('The {profile}.{scan}.service-detection command appears to reference a port list but there is no port-scan section defined in {profile}.{scan}. Define a port-scan section with a command and corresponding pattern that extracts port numbers from the result, or replace the reference with a static list of ports.')
                            errors = True

                    if 'pattern' not in port_scan_profiles_config[profile][scan]['service-detection']:
                        auxiliary.error('The {profile}.{scan}.service-detection section does not have a pattern defined. Every service-detection section must have a command and a corresponding pattern that extracts the protocol (TCP/UDP), port, and service from the results.')
                        errors = True
                    else:
                        if not all(x in port_scan_profiles_config[profile][scan]['service-detection']['pattern'] for x in ['(?P<port>', '(?P<protocol>', '(?P<service>']):
                            auxiliary.error('The {profile}.{scan}.service-detection pattern does not contain one or more of the following matching groups: port, protocol, service. Ensure that all three of these matching groups are defined and capture the relevant data, e.g. (?P<port>\d+)')
                            errors = True

                if 'port-scan' in port_scan_profiles_config[profile][scan]:
                    if 'command' not in port_scan_profiles_config[profile][scan]['port-scan']:
                        auxiliary.error('The {profile}.{scan}.port-scan section does not have a command defined. Every port-scan section must have a command and a corresponding pattern that extracts the port from the results.')
                        errors = True

                    if 'pattern' not in port_scan_profiles_config[profile][scan]['port-scan']:
                        auxiliary.error('The {profile}.{scan}.port-scan section does not have a pattern defined. Every port-scan section must have a command and a corresponding pattern that extracts the port from the results.')
                        errors = True
                    else:
                        if '(?P<port>' not in port_scan_profiles_config[profile][scan]['port-scan']['pattern']:
                            auxiliary.error('The {profile}.{scan}.port-scan pattern does not contain a port matching group. Ensure that the port matching group is defined and captures the relevant data, e.g. (?P<port>\d+)')
                            errors = True
            break

    if not found_scan_profile:
        auxiliary.error('Argument --profile: must reference a port scan profile defined in {port_scan_profiles_config_file}. No such profile found: {port_scan_profile}')
        errors = True

    if len(args.targets) == 0 and not len(args.target_file):
        auxiliary.error('You must specify at least one target to scan!')
        errors = True


    for target in args.targets:
        targets, failed = targetlist.get_ip_address(target, targets, args.disable_sanity_checks)
        if failed: errors = True

    if len(args.target_file) > 0:
        targets, errors = targetlist.read_targets_from_file(args.target_file, targets, args.disable_sanity_checks)

    if not args.disable_sanity_checks and len(targets) > 256:
        auxiliary.error('A total of ' + str(len(targets)) + ' targets would be scanned. If this is correct, re-run with the --disable-sanity-checks option to suppress this check.')
        errors = True

    if not os.getuid() == 0:
        auxiliary.warn('Warning: You are not running the program with superuser privileges. Service scanning may be impacted.')

    return (errors, targets)
