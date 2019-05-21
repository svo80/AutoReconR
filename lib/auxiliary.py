#!/usr/bin/env python3

import sys
import string
import pprint
from colorama import Fore, Style
from datetime import datetime

class objectview(object):
    def __init__(self, dic):
        self.__dict__ = dic

def e(*args, frame_index=1, **kvargs):
    frame = sys._getframe(frame_index)

    vals = {}

    vals.update(frame.f_globals)
    vals.update(frame.f_locals)
    vals.update(kvargs)

    return string.Formatter().vformat(' '.join(args), args, vals)

def get_time(time = None, delta = False, format_string = '%H:%M:%S'):
    if not time: time = datetime.now()
    if isinstance(time, datetime): time = time.strftime(format_string)
    return time if not delta else datetime.strptime(time, format_string)

def pretty_print(obj):
    pp = pprint.PrettyPrinter(indent=2)
    pp.pprint(obj)

def cprint(*args, color=Fore.RESET, char='*', sep=' ', end='\n', frame_index=1, file=sys.stdout, **kvargs):
    frame = sys._getframe(frame_index)

    vals = {
        'bgreen':  Fore.GREEN  + Style.BRIGHT,
        'bred':    Fore.RED    + Style.BRIGHT,
        'bblue':   Fore.BLUE   + Style.BRIGHT,
        'byellow': Fore.YELLOW + Style.BRIGHT,
        'bmagenta': Fore.MAGENTA + Style.BRIGHT,

        'green':  Fore.GREEN,
        'red':    Fore.RED,
        'blue':   Fore.BLUE,
        'yellow': Fore.YELLOW,
        'magenta': Fore.MAGENTA,

        'bright': Style.BRIGHT,
        'srst':   Style.NORMAL,
        'crst':   Fore.RESET,
        'rst':    Style.NORMAL + Fore.RESET
    }

    vals.update(frame.f_globals)
    vals.update(frame.f_locals)
    vals.update(kvargs)

    clock = get_time()
    clock = sep + '['  + Style.BRIGHT + Fore.YELLOW + clock + Style.NORMAL + Fore.RESET + ']'
    unfmt = ''
    if char is not None:
        unfmt += color + '[' + Style.BRIGHT + char + Style.NORMAL + ']' + Fore.RESET + clock + sep
    unfmt += sep.join(args)

    fmted = unfmt

    for attempt in range(10):
        try:
            fmted = string.Formatter().vformat(unfmt, args, vals)
            break
        except KeyError as err:
            key = err.args[0]
            unfmt = unfmt.replace('{' + key + '}', '{{' + key + '}}')

    print(fmted, sep=sep, end=end, file=file)

def debug(*args, color=Fore.BLUE, sep=' ', end='\n', file=sys.stdout, verbose=0, **kvargs):
    if verbose >= 2:
        cprint(*args, color=color, char='-', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def info(*args, sep=' ', end='\n', file=sys.stdout, **kvargs):
    cprint(*args, color=Fore.GREEN, char='*', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def warn(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
    cprint(*args, color=Fore.YELLOW, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def error(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
    cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def fail(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
    cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)
    sys.exit(-1)

def get_header(version):
    logo = r'''
           _____          __        __________                          __________
          /  _  \  __ ___/  |_  ____\______   \ ____   ____  ____   ____\______   \
         /  /_\  \|  |  \   __\/  _ \|       _// __ \_/ ___\/  _ \ /    \|       _/
        /    |    \  |  /|  | (  <_> )    |   \  ___/\  \__(  <_> )   |  \    |   \
        \____|__  /____/ |__|  \____/|____|_  /\___  >\___  >____/|___|  /____|_  /
                \/                          \/     \/     \/           \/       \/
        '''

    print('\n{0}'.format('-' * 90))
    print('{0}'.format(logo))
    print('{0} v{1}'.format(' ' * (90 - len(version) - 2), version))
    print('\n\tAutomated network reconnaissance and reporting.')
    print('\n{0}\n'.format('-' * 90))

