#!/usr/bin/env python3
# Andreas Hunkeler, @Karneades (2019)
# https://github.com/Karneades/SigmaFilterCheck

import argparse
import yaml
import os
import sys
import re
import glob

class Rule:
    rule = ""
    condition = ""
    filtername = ""
    filters = []
    isDangerous = False

    def __init__(self, path, condition):
        self.rule = path
        self.condition = condition

    def __init__(self):
        self.rule = ""
        self.condition = ""
        self.filtername = ""
        self.filters = []
        self.isDangerous = False

    def get_filter(self):
        return self.filters

    def set_filter(self,filter):
        self.filters = filter

    def add_filtername(self,name):
        self.filtername = name

    def add_rulefile(self,path):
        self.rule = path

    def add_condition(self,condition):
        self.condition = condition

    def get_rule(self):
        output = []
        output.append(self.rule)
        output.append(self.condition)
        output.append(", ".join(self.filtername))
        output.append(self.get_filter())
        return output

    def __str__(self):
        return yaml.dump(self.get_rule(), explicit_start=True, default_flow_style=False)

def checkRule(rule, filter):
    filterValues = []
    for f in filter:
        if (f.endswith('*')):
            f = f.replace("*","")
            for s in rule['detection']:
                if s.startswith(f):
                    for fi in rule,rule['detection'][s]:
                        dangerousFilters = checkFilter(fi)
                        if dangerousFilters:
                            filterValues.append({s:dangerousFilters})
        else:
            dangerousFilters = checkFilter(rule['detection'][f])
            if dangerousFilters:
                filterValues.append({f:dangerousFilters})

    return filterValues

def checkFilter(filter):
    filterValues = []
    ret = []

    if (isinstance(filter, list)):
        for k in filter:
            ret = checkFilter(k)
            if ret:
                filterValues.append(ret)
    elif (isinstance(filter, dict)):
        for k in filter:
            if args.field == "all" or k.lower() == (args.field).lower():
                ret = checkFilterValue(k,filter[k])
                if ret:
                    filterValues.append(ret)

    return filterValues

def checkFilterValue(fieldname, value):
    filterValue = {}
    filterValueList = []

    if (isinstance(value,(dict,list))):
        for v in value:
            if (str(v).startswith("*")):
                filterValueList.append(v)
    else:
        if (str(value).startswith("*")):
            filterValueList.append(value)

    if filterValueList:
        filterValue = {fieldname:filterValueList}

    return filterValue

def extractFilter(line):
    filters = []
    matches = []

    matches = re.findall(r'not \(?\s*1 of \s*([\w\*]*)\s*\)?|not \(?\s*all of \s*([\w\*]*)\s*\)?|not \s*([^\d\(][^\)\s]*)|not \(\s*([^\d]+.*)\s?\)',line)

    for match in matches:
        if match[3]: # group for correspond to not (filter 1 or filter 2 ...)
            for m in re.findall(r'(?: or )?([\*\w]+)',match[3]):
                filters.append(m)
        else:
            for filter in match:
                if filter:
                    filters.append(filter)
    return filters

## main ##

parser = argparse.ArgumentParser(description='Check Sigma rules for easy-to-bypass whitelist values.')
parser.add_argument('path',help='path to one Sigma rule or directory')
parser.add_argument('--field',default="all",help='check only whitelist values for the given field name (case insensitive matching, default: all)')
parser.add_argument('--nostats',action='store_true',help='hide stats (default: false)')
args = parser.parse_args()

wildcardWhitelist = 0

files = []
if (os.path.isfile(args.path)):
    files = [args.path]
else:
    files = glob.glob(args.path + '/**/*.yml', recursive=True)

for file in files:

    with open(file) as stream:
        try:
            rules = list(yaml.safe_load_all(stream))
        except:
            print ("Error parsing: " + file)

    for rule in rules:

        sigmaRule = Rule()

        filter = []
        filterValues = []
        condition = ""

        if ( 'detection' in rule.keys() ):
            detection = rule['detection']
        else:
            continue

        if ( 'condition' in detection.keys() ):
            condition  = str(detection['condition'])
        else:
            continue

        if ( 'not' not in condition ):
            continue

        sigmaRule.add_rulefile(file)
        sigmaRule.add_condition(condition)

        filter = extractFilter(condition)
        sigmaRule.add_filtername(filter)

        filterValues = checkRule(rule, filter)
        sigmaRule.set_filter(filterValues)

        if sigmaRule.get_filter():
            wildcardWhitelist += 1
            print(sigmaRule)

if (not args.nostats):
    print ("")
    print ("Number of rules with wildecards in whitelist: " + str(wildcardWhitelist))
    print ("Number of rules checked:                      " + str(len(files)))
