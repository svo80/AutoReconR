#!/usr/bin/env python3

import ipaddress
import os
import socket

def read_targets_from_file(filename, targets, disable_sanity_checks):

    if not os.path.isfile(filename):
        auxiliary.error('The file {filename} with target information was not found.')
        return (targets, True)

    try:
        with open(filename, 'r') as f:
            entries = f.read()
    except OSError:
        auxiliary.error('The file {filename} with target information could not be read.')
        return (targets, True)

    error = False
    for ip in entries.split('\n'):
        if ip.startswith('#') or len(ip) == 0: continue
        
        targets, failed = get_ip_address(ip, targets, disable_sanity_checks)
        if failed: error = True
    
    return (targets, error)

def get_ip_address(target, targets, disable_sanity_checks):

    errors = False
    try:
        ip = str(ipaddress.ip_address(target))

        if ip not in targets:
            targets.append(ip)
    except ValueError:
        try:
            target_range = ipaddress.ip_network(target, strict=False)
            if not disable_sanity_checks and target_range.num_addresses > 256:
                auxiliary.error(target + ' contains ' + str(target_range.num_addresses) + ' addresses. Check that your CIDR notation is correct. If it is, re-run with the --disable-sanity-checks option to suppress this check.')
                errors = True
            else:
                for ip in target_range.hosts():
                    ip = str(ip)
                    if ip not in targets:
                        targets.append(ip)
        except ValueError:
            try:
                ip = socket.gethostbyname(target)
                if target not in targets:
                    targets.append(target)
            except socket.gaierror:
                auxiliary.warn(target + ' does not appear to be a valid IP address, IP range, or resolvable hostname.')

    return (targets, errors)

