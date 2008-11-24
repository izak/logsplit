#!/usr/bin/python

import re, sys, traceback, os, ConfigParser
from optparse import OptionParser

default_storage = '/var/log/logsplit'
default_logfile = '/var/log/logsplit/access.default.log'
default_conf    = '/etc/logsplit/logsplit.conf'
error_logfile   = '/var/log/logsplit/error.log'

class LogDomain:
    regexp = None
    logfile = None

    def __init__(self, regexp, logfile):
        self.regexp, self.logfile = regexp, logfile

def init(rules, base):
    compiled_rules = []
    for rule in rules:
        regexp = re.compile(rule[0])
        if(rule[1].startswith('/')):
            fp = open(rule[1], "a")
        else:
            fp = open(os.path.join(base, rule[1]), "a")
        compiled_rules.append(LogDomain(regexp, fp))
    return compiled_rules

def shutdown(compiled_rules):
    for rule in compiled_rules:
        rule.logfile.close()

def log(filename, line):
    fp = open(filename, "a")
    fp.write(line)
    fp.close()

def accesslog(rules, line, defaultlog):
    for domain in rules:
        m = domain.regexp.match(line)
        if m is not None:
            domain.logfile.write(line)
            return
        # Nothing matched, log default log file
        log(defaultlog, line)

def parseconfig(cfgfile):
    splitrules = []
    config = ConfigParser.ConfigParser()
    config.read([cfgfile,])
    for site in config.sections():
        splitrules.append((config.get(site, 'regex'), config.get(site, 'file')))
    return splitrules
        

def main():
    parser = OptionParser()
    parser.add_option("-b", "--base",
        help="Log base directory, domain log files are stored here", default=default_storage)
    parser.add_option("-c", "--config",
        help="Configuration for log splitting", default=default_conf)
    parser.add_option("-d", "--defaultlog",
        help="Default log file if no domain matches", default=default_logfile)
    parser.add_option("-e", "--errorlog",
        help="Error log file", default=error_logfile)
    (options, args) = parser.parse_args()

    splitrules = parseconfig(options.config)
    rules = init(splitrules, options.base)

    stdin_readline = sys.stdin.readline
    line = stdin_readline()
    try:
        while line:
            accesslog(rules, line, options.defaultlog)
            line = stdin_readline()
    except:
        log(options.errorlog, traceback.format_exc())
        # Re-raise, squid exits when last logger dies
        raise
    shutdown(rules)

if __name__ == "__main__":
    main()
