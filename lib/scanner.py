#!/usr/bin/env python3

import asyncio
import os
import random
import re
import glob
import string
from concurrent.futures import FIRST_COMPLETED
from lib import auxiliary

class Target:
    def __init__(self, address, config):
        self.address = address
        self.config = config
        self.basedir = ''
        self.reportdir = ''
        self.scandir = ''
        self.scans = []
        self.lock = None

def scan_host(target, args):
    auxiliary.info('Scanning target {byellow}{target.address}{rst}.')
    
    basedir = os.path.abspath(os.path.join(args.output, target.address))
    target.basedir = basedir
    os.makedirs(basedir, exist_ok=True)

    exploitdir = os.path.abspath(os.path.join(basedir, 'exploit'))
    os.makedirs(exploitdir, exist_ok=True)
    
    exploitdir = os.path.abspath(os.path.join(basedir, 'privilege_escalation'))
    os.makedirs(exploitdir, exist_ok=True)

    lootdir = os.path.abspath(os.path.join(basedir, 'loot'))
    os.makedirs(lootdir, exist_ok=True)

    reportdir = os.path.abspath(os.path.join(basedir, 'report'))
    target.reportdir = reportdir
    os.makedirs(reportdir, exist_ok=True)

    screenshotdir = os.path.abspath(os.path.join(reportdir, 'screenshots'))
    os.makedirs(screenshotdir, exist_ok=True)

    scandir = os.path.abspath(os.path.join(basedir, 'scans'))
    target.scandir = scandir
    os.makedirs(scandir, exist_ok=True)
    prepare_log_files(scandir, target)

    os.makedirs(os.path.abspath(os.path.join(scandir, 'xml')), exist_ok=True)

    open(os.path.abspath(os.path.join(reportdir, 'local.txt')), 'a').close()
    open(os.path.abspath(os.path.join(reportdir, 'proof.txt')), 'a').close()

    # Use a lock when writing to specific files that may be written to by other asynchronous functions.
    target.lock = asyncio.Lock()

    # Create a semaphore to limit number of concurrent scans.
    semaphore = asyncio.Semaphore(args.concurrent_scans)
   
    # Get event loop for current process.
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(scan_services(loop, semaphore, target, args))
        auxiliary.info('Finished scanning target {byellow}{target.address}{rst}.')
        
        if not args.no_report:
            loop.run_until_complete(create_report(target, args))
    except KeyboardInterrupt:
        sys.exit(1)

async def get_status(target, period=10):
    while True:
        await asyncio.sleep(period)
        tasks = len(asyncio.all_tasks())
        auxiliary.info('{bgreen}Info{rst}: Remaining tasks for target {byellow}{target}{rst}: {tasks}')

async def scan_services(loop, semaphore, target, args):
    address = target.address
    scandir = target.scandir
    files = target.config['files']
    applications = auxiliary.objectview(target.config['applications'])
    wordlists = auxiliary.objectview(target.config['wordlists'])
    pending = []

    port_scan_profiles_config = target.config['port_scan_profiles']
    service_scans_config = target.config['service_scan_profiles']
    port_scan_profile = args.profile
    
    nmap_default_options = args.nmap
    if args.nmap_append:
        nmap_default_options += " " + args.nmap_append

    for profile in port_scan_profiles_config:
        if profile == port_scan_profile:
            for scan in port_scan_profiles_config[profile]:
                scan_profile = port_scan_profiles_config[profile][scan]
                service_detection = (scan_profile['service-detection']['command'], scan_profile['service-detection']['pattern'])
                if 'port-scan' in scan_profile:
                    port_scan = (scan_profile['port-scan']['command'], scan_profile['port-scan']['pattern'])
                    pending.append(run_portscan(semaphore, scan, target, service_detection, port_scan, args = args))
                else:
                    pending.append(run_portscan(semaphore, scan, target, service_detection, args = args))
            break

    services = []

    if args.heartbeat > 0: heartbeat = asyncio.create_task(get_status(address, args.heartbeat))
    while True:
        if not pending:
            if args.heartbeat > 0: heartbeat.cancel()
            break
        
        done, pending = await asyncio.wait(pending, return_when=FIRST_COMPLETED)
        for task in done:
            result = task.result()
            if result['returncode'] == 0:
                if result['name'] == 'run_portscan':
                    for service_tuple in result['services']:
                        if service_tuple not in services:
                            services.append(service_tuple)
                        else:
                            continue

                        protocol = service_tuple[0]
                        port = service_tuple[1]
                        service = service_tuple[2]

                        auxiliary.info('Port {bmagenta}{protocol} {port}{rst} ({bmagenta}{service}{rst}) open on target {byellow}{address}{rst}.')
                        async with target.lock:
                            with open(os.path.join(target.scandir, files['notes']), 'a') as file:
                                file.writelines(auxiliary.e('[*] Port {protocol} {port} ({service}) open on {address}.\n\n'))

                        if protocol == 'udp':
                            nmap_extra = nmap_default_options + " -sU"
                        else:
                            nmap_extra = nmap_default_options

                        secure = True if 'ssl' in service or 'tls' in service else False

                        # Special cases for HTTP.
                        scheme = 'https' if 'https' in service or 'ssl' in service or 'tls' in service else 'http'

                        if service.startswith('ssl/') or service.startswith('tls/'):
                            service = service[4:]

                        for service_scan in service_scans_config:
                            # Skip over configurable variables since the python toml parser can iterate over tables only.
                            if service_scan in ['username_wordlist', 'password_wordlist']:
                                continue

                            ignore_service = False
                            if 'ignore-service-names' in service_scans_config[service_scan]:
                                for ignore_service_name in service_scans_config[service_scan]['ignore-service-names']:
                                    if re.search(ignore_service_name, service):
                                        ignore_service = True
                                        break

                            if ignore_service:
                                continue

                            matched_service = False

                            if 'service-names' in service_scans_config[service_scan]:
                                for service_name in service_scans_config[service_scan]['service-names']:
                                    if re.search(service_name, service):
                                        matched_service = True
                                        break

                            if not matched_service:
                                continue

                            # INFO: change for saving results in directories per service
                            if scheme == 'https' or service_scan == 'all_services':
                                category = 'https/'
                            else:
                                category = '{0}/'.format(service_scan) 
                            
                            try:
                                servicedir = os.path.join(scandir, category)
                                if not os.path.exists(servicedir): os.mkdir(servicedir)
                                xmldir = os.path.join(scandir, 'xml', category)
                                if not os.path.exists(xmldir): os.mkdir(xmldir)
                            except OSError:
                                category = ''

                            if 'manual' in service_scans_config[service_scan]:
                                heading = False
                                with open(os.path.join(scandir, files['manual_commands']), 'a') as file:
                                    for manual in service_scans_config[service_scan]['manual']:
                                        if 'description' in manual:
                                            if not heading:
                                                file.writelines(auxiliary.e('[*] {service} on {protocol}/{port}\n\n'))
                                                heading = True
                                            description = manual['description']
                                            file.writelines(auxiliary.e('\t[-] {description}\n\n'))
                                        if 'commands' in manual:
                                            if not heading:
                                                file.writelines(auxiliary.e('[*] {service} on {protocol}/{port}\n\n'))
                                                heading = True
                                            for manual_command in manual['commands']:
                                                try:
                                                    manual_command = auxiliary.e(manual_command)
                                                    file.writelines('\t\t' + auxiliary.e('{manual_command}\n\n'))
                                                except KeyError:
                                                    auxiliary.error('Command {bred}could not be documented{rst} on {byellow}{address}{rst}: {manual_command}.')
                                    if heading:
                                        file.writelines('\n')

                            if 'scan' in service_scans_config[service_scan]:
                                for scan in service_scans_config[service_scan]['scan']:
                                    if 'name' in scan:
                                        name = scan['name']
                                       
                                        limit_to = scan['limit_to'] if 'limit_to' in scan else []
                                        
                                        if (len(limit_to) > 0) and port not in limit_to:
                                            auxiliary.info('[{bgreen}Info{rst}] Scan profile {bgreen}{name}{rst} should not be run for port {bgreen}{port}{rst} on target {byellow}{address}{rst} and is ignored.')
                                            continue

                                        # INFO: change for supporting different complexity levels during service scanning
                                        run_level = scan['level'] if 'level' in scan else 0
                                        if ((max(args.run_level) > 0) and ((not args.run_only and run_level > max(args.run_level)) or (args.run_only and not run_level in args.run_level))):    
                                            if args.verbose >= 1:
                                                auxiliary.info('[Info] Scan profile {bgreen}{name}{rst} is at a {bgreen}different complexity level{rst} and is ignored for target {byellow}{address}{rst}.')
                                            continue

                                        if 'command' in scan:
                                            tag = auxiliary.e('{protocol}/{port}/{name}')
                                            command = scan['command']

                                            if 'ports' in scan:
                                                port_match = False

                                                if protocol == 'tcp':
                                                    if 'tcp' in scan['ports']:
                                                        for tcp_port in scan['ports']['tcp']:
                                                            if port == tcp_port:
                                                                port_match = True
                                                                break
                                                elif protocol == 'udp':
                                                    if 'udp' in scan['ports']:
                                                        for udp_port in scan['ports']['udp']:
                                                            if port == udp_port:
                                                                port_match = True
                                                                break

                                                if port_match == False:
                                                    auxiliary.warn('{yellow}[{bright}{tag}{srst}] Scan cannot be run against {protocol} port {port}. Skipping.{rst}')
                                                    continue

                                            if 'run_once' in scan and scan['run_once'] == True:
                                                scan_tuple = (name,)
                                                if scan_tuple in target.scans:
                                                    auxiliary.warn('{yellow}[{bright}{tag} on {address}{srst}] Scan should only be run once it appears once, and it appears to have already been queued. Skipping.{rst}')
                                                    continue
                                                else:
                                                    target.scans.append(scan_tuple)
                                            else:
                                                scan_tuple = (protocol, port, service, name)
                                                if scan_tuple in target.scans:
                                                    auxiliary.warn('{yellow}[{bright}{tag} on {address}{srst}] Scan appears to have already been queued but it is not marked as run_once in service-scans.toml. Possible duplicate tag? Skipping.{rst}')
                                                    continue
                                                else:
                                                    target.scans.append(scan_tuple)

                                            patterns = []
                                            if 'pattern' in scan:
                                                patterns = scan['pattern']

                                            try:
                                                pending.add(asyncio.ensure_future(run_cmd(semaphore, auxiliary.e(command), target, category=category, tag=tag, scheme=scheme, patterns=patterns, args=args)))
                                            except KeyError: 
                                                auxiliary.error('Service detection {bred}{tag}{rst} on {byellow}{address}{rst} could not be started' + (' with {bblue}{command}{rst}.' if args.verbose >= 1 else '.'))

                elif result['name'] == 'run_cmd':
                    if (not args.skip_post_processing) and ('post_processing') in result and (len(result['post_processing']) > 0):
                        for resource, module in result['post_processing']:
                            for item in module: 
                                module_name = item[0]
                                post_processor = item[1]
                                module_command = item[2]

                                auxiliary.info('Adding post-processing module {bmagenta}{module_name}{rst} ({bmagenta}{post_processor}{rst}) on target {byellow}{address}{rst}' + (' for resource {bblue}{resource}{rst}.' if args.verbose >= 1 else '.'))
                                post_processor = '{0}/{1}'.format(post_processor, module_name)
                                # do not perform post processing anymore when patterns on deeper levels match
                                # TODO: possibly support post-processing modules up to a certain depth
                                pending.add(asyncio.ensure_future(run_cmd(semaphore, auxiliary.e(module_command), target, category=category, tag=post_processor, scheme=scheme, patterns=patterns, args=args, post_process=False)))

async def run_portscan(semaphore, tag, target, service_detection, port_scan=None, args = None):
    async with semaphore:
        address = target.address
        scandir = target.scandir
        files = target.config['files']
        applications = auxiliary.objectview(target.config['applications'])
        nmap_extra = args.nmap

        if args.nmap_append:
            nmap_extra += " " + args.nmap_append

        ports = ''
        if port_scan is not None:
            command = auxiliary.e(port_scan[0])
            pattern = port_scan[1]

            auxiliary.info('Running port scan {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{command}{rst}.' if args.verbose >= 1 else '.'))

            async with target.lock:
                with open(os.path.join(scandir, files['commands']), 'a') as file:
                    file.writelines(auxiliary.e('{command}\n\n'))

            process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')

            output = [
                parse_port_scan(process.stdout, tag, target, pattern, args),
                read_stream(process.stderr, target, tag=tag, color='{red}', args=args)
            ]

            results = await asyncio.gather(*output)
            await process.wait()
            
            if process.returncode != 0:
                auxiliary.error('Port scan {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {process.returncode}')
                async with target.lock:
                    with open(os.path.join(scandir, files['errors']), 'a') as file:
                        file.writelines(auxiliary.e('[*] Port scan {tag} returned non-zero exit code: {process.returncode}. Command: {command}\n'))
                return {'returncode': process.returncode}
            else:
                auxiliary.info('Port scan {bblue}{tag}{rst} on {byellow}{address}{rst} finished successfully')

            ports = results[0]
            if len(ports) == 0:
                return {'returncode': -1}

            ports = ','.join(ports)

        try:
            command = auxiliary.e(service_detection[0])
            pattern = service_detection[1]
        except (KeyError, AttributeError) as err:
            auxiliary.error('Service detection {bred}{tag}{rst} on {byellow}{address}{rst} could not be started' + (' (Error {bred}{err}{rst}.' if args.verbose >=1 else '.'))
            async with target.lock:
                with open(os.path.join(scandir, files['errors']), 'a') as file:
                    file.writelines(auxiliary.e('[*] Service detection {tag} could not be started: {err}\n'))
            return {'returncode': err}

        auxiliary.info('Running service detection {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{command}{rst}.' if args.verbose >= 1 else '.'))
        async with target.lock:
            with open(os.path.join(scandir, files['commands']), 'a') as file:
                file.writelines(auxiliary.e('{command}\n\n'))

        process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')

        output = [
            parse_service_detection(process.stdout, tag, target, pattern, args),
            read_stream(process.stderr, target, tag=tag, color='{red}', args=args)
        ]

        results = await asyncio.gather(*output)
        await process.wait()

        if process.returncode != 0:
            auxiliary.error('Service detection {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {process.returncode}')
            async with target.lock:
                with open(os.path.join(scandir, files['errors']), 'a') as file:
                    file.writelines(auxiliary.e('[*] Service detection {tag} returned non-zero exit code: {process.returncode}. Command: {command}\n'))
        else:
            auxiliary.info('Service detection {bblue}{tag}{rst} on {byellow}{address}{rst} finished successfully.')

        services = results[0]

        return {'returncode': process.returncode, 'name': 'run_portscan', 'services': services}

async def parse_service_detection(stream, tag, target, pattern, args):
    address = target.address
    files = target.config['files'] 
    global_patterns = target.config['patterns']
    services = []
    
    while True:
        line = await stream.readline()
        if line:
            line = str(line.rstrip(), 'utf8', 'ignore')
            auxiliary.debug('{blue}[{bright}{address} {tag}{srst}]{rst} {line}', verbose=args.verbose)

            parse_match = re.search(pattern, line)
            if parse_match:
                services.append((parse_match.group('protocol').lower(), int(parse_match.group('port')), parse_match.group('service')))

            for p in global_patterns:
                matches = re.findall(p['pattern'], line)
                if 'description' in p:
                    for match in matches:
                        if args.verbose >= 1:
                            auxiliary.info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}' + p['description'].replace('{match}', '{bblue}{match}{crst}{bmagenta}') + '{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, files['patterns']), 'a') as file:
                                file.writelines(auxiliary.e('{tag} - ' + p['description'] + '\n\n'))
                else:
                    for match in matches:
                        if args.verbose >= 1:
                            auxiliary.info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}Matched Pattern: {bblue}{match}{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, files['patterns']), 'a') as file:
                                file.writelines(auxiliary.e('{tag} - Matched Pattern: {match}\n\n'))
        else:
            break

    return services

async def parse_port_scan(stream, tag, target, pattern, args):
    address = target.address
    files = target.config['files']
    ports = []

    while True:
        line = await stream.readline()
        if line:
            line = str(line.rstrip(), 'utf8', 'ignore')
            auxiliary.debug('{blue}[{bright}{address} {tag}{srst}]{rst} {line}', verbose=args.verbose)

            parse_match = re.search(pattern, line)
            if parse_match:
                ports.append(parse_match.group('port'))

            for p in global_patterns:
                matches = re.findall(p['pattern'], line)
                if 'description' in p:
                    for match in matches:
                        if args.verbose >= 1:
                            auxiliary.info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}' + p['description'].replace('{match}', '{bblue}{match}{crst}{bmagenta}') + '{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, files['patterns']), 'a') as file:
                                file.writelines(auxiliary.e('{tag} - ' + p['description'] + '\n\n'))
                else:
                    for match in matches:
                        if args.verbose >= 1:
                            auxiliary.info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}Matched Pattern: {bblue}{match}{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, files['patterns']), 'a') as file:
                                file.writelines(auxiliary.e('{tag} - Matched Pattern: {match}\n\n'))
        else:
            break

    return ports

async def run_cmd(semaphore, cmd, target, category='?', tag='?', scheme='?', patterns=[], args=None, post_process = True):
    async with semaphore:
        address = target.address
        files = target.config['files']
        scandir = target.scandir
        hits = []

        auxiliary.info('Running task {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{cmd}{rst}.' if args.verbose >= 1 else '.'))

        async with target.lock:
            with open(os.path.join(scandir, files['commands']), 'a') as file:
                file.writelines(auxiliary.e('{category} - {cmd}\n\n'))
        
        # skip extended service scanning if only respective commands should be documented 
        if args.skip_service_scan: 
            auxiliary.info('Task {bblue}{tag}{rst} on {byellow}{address}{rst} finished successfully.')
            return {'returncode': 0, 'name': 'run_cmd'}
        
        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')

        output = [    
            read_stream(process.stdout, target, category=category, tag=tag, scheme=scheme, patterns=patterns, args=args, post_process=post_process),
            read_stream(process.stderr, target, category=category, tag=tag, scheme=scheme, patterns=patterns, color='{red}', args=args, post_process=post_process)
        ]
        await process.wait()
        results = await asyncio.gather(*output)
    if process.returncode != 0:
        auxiliary.error('Task {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {process.returncode}.')
        async with target.lock:
            with open(os.path.join(scandir, files['errors']), 'a') as file:
                file.writelines(auxiliary.e('[*] Task {tag} returned non-zero exit code: {process.returncode}. Command: {cmd}\n'))
    else:
        auxiliary.info('Task {bblue}{tag}{rst} on {byellow}{address}{rst} finished successfully.')

    return {'returncode': process.returncode, 'name': 'run_cmd', 'post_processing' : results[0]}

async def read_stream(stream, target, category = '?', tag='?', scheme='?', patterns=[], color='', args=None, post_process=True):
    address = target.address
    scandir = target.scandir
    files = target.config['files']
    applications = auxiliary.objectview(target.config['applications'])
    
    # consider both global as well as service-specific patterns
    patterns += target.config['patterns']
    hits = []

    while True:
        line = await stream.readline()
        if line:
            line = str(line.rstrip(), 'utf8', 'ignore')
            auxiliary.debug('[{bgreen}{address} {tag}{srst}]{rst} {line}', verbose=args.verbose)

            for p in patterns:
                matches = re.findall(p['pattern'], line)
                post_processing_exceptions = p['except'] if 'except' in p else []

                for match in matches:
                    if 'description' in p:
                        if args.verbose >= 1:
                            auxiliary.info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}' + p['description'].replace('{match}', '{bblue}{match}{crst}{bmagenta}') + '{rst}')
                        
                        async with target.lock:
                            with open(os.path.join(target.scandir, files['patterns']), 'a') as file:
                                file.writelines(auxiliary.e('{tag} - ' + p['description'] + '\n\n'))
                    else:
                        if args.verbose >= 1:
                            auxiliary.info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}Matched Pattern: {bblue}{match}{rst}')
                        
                        async with target.lock:
                            with open(os.path.join(target.scandir, files['patterns']), 'a') as file:
                                file.writelines(auxiliary.e('{tag} - Matched Pattern: {match}\n\n'))
                   
                    # perform any post-processing tasks when a pattern matched
                    if (not args.skip_post_processing) and (post_process) and ('post_processor' in p) and (match not in hits):
                        post_processing = []
                        
                        for module in p['post_processor']:
                            module_name = module['name'] if 'name' in module else ''
                            module_command = module['command'] if 'command' in module else ''
                            protocol, port, application = tag.split('/')

                            # merge the pattern- and module-specific exceptions
                            exceptions = post_processing_exceptions.copy()
                            if 'except' in module:
                                for exception in module['except']:
                                    if exception not in exceptions: exceptions.append(exception)
                                
                            exception_entry = False
                            # TODO: ugly hack to save filename for a URL, needs correction
                            record = '{0}_{1}'.format(os.path.basename(match.rstrip('/')),  ''.join(random.choices(string.digits, k=5)))
                            for exception in exceptions:
                                entry = re.search(exception, record, flags=re.IGNORECASE)
                                if entry:
                                    exception_entry = True
                                    if args.verbose >= 1:
                                        auxiliary.info('[{bgreen}{address} {tag}{srst}]{rst} Post processing module {bgreen}{module_name}{rst} is not executed for resource {match}.', verbose=args.verbose)
                                    break
                            
                            if len(module_command) > 0 and not exception_entry:
                                post_processing.append( (module_name, tag, auxiliary.e(module_command) ))
                        
                        if (match not in hits) and (len(post_processing) > 0): hits.append( (match, post_processing) )
        else:
            break

    return hits

async def create_report(target, args):
    address = target.address
    scandir = target.scandir
    reportdir = target.reportdir
    files = target.config['files']
    applications = auxiliary.objectview(target.config['applications'])

    #types = ('*.txt') 
    #filenames = []
    #[filenames.extend(glob.glob(os.path.join(scandir, '*', filetype), recursive=True)) for filetype in types]
    filenames = glob.glob(os.path.join(scandir, '**', '*.txt'), recursive=True)
    filenames.sort()
    report_order = ' '.join(filenames)
    
    try:
       command = auxiliary.e('{} {} -o - | {} - {}'.format(applications.enscript, report_order, applications.ps2pdf, os.path.join(reportdir, files['report'])))
    except AttributeError as err:
        auxiliary.error('Task {bred}report creation{rst} on {byellow}{address}{rst} could not be started' + (' (Error {bred}{err}{rst}.' if args.verbose >=1 else '.'))
        async with target.lock:
            with open(os.path.join(scandir, files['errors']), 'a') as file:
                file.writelines(auxiliary.e('[*] Task report creation could not be started: {err}\n'))
        return {'returncode': err}

    auxiliary.info('Creating report for target {byellow}{address}{rst}.')
    process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')
    await process.communicate()
    
    if process.returncode != 0:
        auxiliary.error('{bred}Report creation{rst} for target {byellow}{address}{rst} returned non-zero exit code: {process.returncode}.')
    else:
        auxiliary.info('Report for target {byellow}{address}{rst} was created successfully.')

    return {'returncode':process.returncode}

def prepare_log_files(scandir, target):
    files = target.config['files']

    for filename in files:
        try:
            # TODO: files dictionary needs to be reorganized, otherwise some unnecessary files will be created in the scan directory
            if not files[filename].startswith('_'): continue
            caption = 'Log session started for host {0} - {1}\n'.format(target.address, auxiliary.get_time(format_string = '%B %d, %Y - %H:%M:%S'))
            with open(os.path.join(scandir, files[filename]), 'a') as f:
                f.write('\n{}\n'.format('=' * len(caption)))
                f.write(caption)
                f.write('{}\n\n'.format('=' * len(caption)))
        except OSError:
            auxiliary.fail('Error while setting up log file {filename}.')

