# SigmaFilterCheck

SigmaFilterCheck is a python script to search for easy-to-bypass whitelists in
[Sigma](https://github.com/Neo23x0/sigma) rules.

***

<!-- vim-markdown-toc GFM -->

* [Motivation](#motivation)
    * [Examples](#examples)
    * [Ideas](#ideas)
* [Requirements](#requirements)
* [Usage](#usage)
* [Current Usage of Filters](#current-usage-of-filters)
* [Pull Requests](#pull-requests)
* [Example](#example)
* [Other Issues](#other-issues)
* [Credits](#credits)

<!-- vim-markdown-toc -->

***

## Motivation

The purpose of the script is to check Sigma rules for easy-to-bypass
whitelists (values in not-condition of the sigma rule) which could help
attackers bypassing detections and therefore mislead defenders in their
detection confidence. It should help with the discussion **how we as Sigma
community in regards to open source detection rules should work with such
whitelists**. Rules with wildcards on the left side of a whitelist value which
are sometimes fully controlled by attackers are of special interest. Examples
are command line or image path whitelists in Sysmon events or whitelists for
user agents. Below I put together some ideas which could limit the risk of
bypasses.

**Result**: Only a small amount of rules have wildcards on the left side
of the filter. Furthermore, only a subset are easy-to-bypass and are potentially
controlled by an attacker. There are currently 285 rules (as of April 2019) in 
the repo and only 25 of them include wildcards on the left side of the whitelist.
For the 207 Windows rules there are 21 with such a whitelist and of the sub
category for process_creation 16 rules were found having wildcards on the
left side of the whitelist value.

**The question is whether we should reduce false positives or whether
we should try to reduce the possibility for bypasses. It's up to the reader
to decide which is more likely.**

_Whitelists are not a problem of Sigma itself but an issue for open source
security detections. As the Cuckoo sandbox developers once said, only provide
a minimal evasion detection and everyone should implement further evasion by
themself._

Initially, I just made pull requests to remove easy-to-bypass whitelist values
in some rules but then thought on checking the whole repository how widespread
such whitelists are. The script could also be used locally before deploying
rules.

There are different ways used to define filters in Sigma rules. See [Sigma
condition
specs](https://github.com/Neo23x0/sigma/wiki/Specification#condition) for more
information about conditions.
- not (x or y ...)
- not (x)
- not (1 of y*)
- not 1 of y*
- not all of y
- not (all of y)
- not 1 of y
- not x

The script first checks if a rule has a "not"-filter, then reads all values
for each field and checks for wildcards. Only rules with such filters are
shown afterwards. For wildcard filters, e.g. "not exclusion*", the
corresponding filters, e.g. exclusion1, exclusion2, ... are used. 

### Examples

For the otherwise valuable generic mshta spawns a shell rule the whitelist
`*/HP/HP*` is used. By just adding a small text to the command line an
attacker could bypass the rule.

```
sigma/rules/windows/process_creation/win_mshta_spawn_shell.yml
detection:
    selection:
        ParentImage: '*\mshta.exe'
        Image:
            - '*\cmd.exe'
            - '*\powershell.exe'
            - '*\wscript.exe'
            - '*\cscript.exe'
            - '*\sh.exe'
            - '*\bash.exe'
            - '*\reg.exe'
            - '*\regsvr32.exe'
            - '*\BITSADMIN*'
    filter:
        CommandLine:
            - '*/HP/HP*'
            - '*\HP\HP*'
    condition: selection and not filter
```

```
mshta vbscript:CreateObject("wscript.Shell").Run("wscript.exe test.js /HP/HP")
```

| Field | Value |
| ------------- | ------------- |
| ParentImage |  C:\Windows\System32\mshta.exe  |
| CommandLine | "C:\Windows\System32\wscript.exe" test.js /HP/HP |

Another example is the following rule which detects the execution of Windows
binary names from an unusual folder. The whitelist includes wildcards in
the image path with the following values:

```
\sigma\rules\windows\process_creation\win_system_exe_anomaly.yml
detection:
    selection:
        Image:
            - '*\svchost.exe'
            - '*\rundll32.exe'
            - '*\services.exe'
            - '*\powershell.exe'
            - '*\regsvr32.exe'
            - '*\spoolsv.exe'
            - '*\lsass.exe'
            - '*\smss.exe'
            - '*\csrss.exe'
            - '*\conhost.exe'
    filter:
        Image:
            - '*\System32\\*'
            - '*\SysWow64\\*'
    condition: selection and not filter
```

An attacker only has to place his binaries inside a subfolder called
`System32` or `SysWow64` and would therefore bypass the rule.

### Ideas

For open source detection rules we could discuss the following ideas

- we could either remove wildcards in whitelists where attackers could potentially control the value. Security teams should create filters based on their logs and environments. Don't throw "intel" away or
- we could put filters to an informative field or
- we could be able to convert the rule without the filters or
- we could create filters as restricted as possible and as difficult to bypass if an attacker gets to know them (which we obviously have to assume for an open source project) or
- we could introduce more restricted character classes which only matches word characters but no path delimiters (which forces every backend to implement such conversion...)
- we could disallow at least wildcards on the left side of the filter for parameters which are sometimes fully controlled by an attacker and
- **we should add CI checks to check for trivial to bypass whitelists.**
  - Instead of using a separate python script we could implement the analyzer
     within a dedicated Sigma backend?
    
    ```
    elif type(node) == sigma.parser.condition.ConditionNOT:
                return self.generateNOTNode(node)
    ```

## Requirements

The module `PyYAML>=3.11` is used to parse the Sigma rules.

``` bash
pip3 install -r requirements.txt
```

## Usage

```
$ python3 sigmacheck.py -h
$ python3 sigmacheck.py ../sigma/rules/
$ python3 sigmacheck.py ../sigma/rules/ --field commandline
$ python3 sigmacheck.py ../sigma/rules/ --field useragent --nostats
$ python3 sigmacheck.py ../sigma/rules/windows/process_creation/win_susp_powershell_enc_cmd.yml
```

See [Example](#example) below.

## Current Usage of Filters

Here is a list of unique conditions with "not" from all Sigma rules (~280).
One of the tests for finding finding filter names based on regex is found on
regex101: https://regex101.com/r/8juK2K/3.

* ( selection_cammute and not filter_cammute ) or ( selection_chrome_frame and not filter_chrome_frame ) or ( selection_devemu and not filter_devemu ) or ( selection_gadget and not filter_gadget ) or ( selection_hcc and not filter_hcc ) or ( selection_hkcmd and not filter_hkcmd ) or ( selection_mc and not filter_mc ) or ( selection_msmpeng and not filter_msmpeng ) or ( selection_msseces and not filter_msseces ) or ( selection_oinfo and not filter_oinfo ) or ( selection_oleview and not filter_oleview ) or ( selection_rc and not filter_rc )
* (exec_selection and not exec_exclusion) or (create_selection and create_keywords)
* (selection1 and not filter1) or selection2 or selection3 or selection4
* all of selection and not (1 of exclusion_*)
* keywords and not 1 of filters
* methregistry or ( methprocess and not filterprocess )
* selection and not ( filter1 or filter2 )
* selection and not ( filter1 or filter2 or filter3 )
* selection and not (ini or intel)
* selection and not 1 of falsepositive*
* selection and not exclusion
* selection and not falsepositive
* selection and not falsepositives
* selection and not filter
* selection and not all of falsepositive
* selection and not (filter)
* selection and not reduction
* selection1 and not selection2
* selection1 or ( selection2 and not filter2 )
* selection_registry and not exclusion_images
* selector | near dllload1 and dllload2 and not exclusion

Test script for extracting filters::

``` bash
$ python regex.py filters.txt
```

``` python
import re
import sys

file = sys.argv[1]

filepath = file

def extractFilter(line):
    filters = []
    matches = []

    matches = re.findall(r'not \(?\s*1 of \s*([\w\*]*)\s*\)?|not \(?\s*all of \s*([\w\*]*)\s*\)?|not \s*([^\d\(][^\)\s]*)|not \(\s*([^\d]+.*)\s?\)',line)

    for match in matches:
        if match[3]:
            for m in re.findall(r'(?: or )?([\*\w]+)',match[3]):
                filters.append(m)
        else:
            for filter in match:
                if filter:
                    filters.append(filter)
    return filters

with open(filepath) as fp:
    line = fp.readline()
    while line:
        print("Line: {}".format(line.strip()))

        print (extractFilter(line))

        print("")

        line = fp.readline()
```

## Pull Requests

After quickly look over the output from the script some pull requets were made to remove such filters.

Rule: sigma/rules/windows/process_creation/win_susp_gup.yml (https://github.com/Neo23x0/sigma/pull/305)
```
Detection:
   {'Image': '*\\GUP.exe'}
Filter:
   {'Image': '*\\updater\\*'}
```

Rule: sigma/rules/windows/process_creation/win_mshta_spawn_shell.yml (https://github.com/Neo23x0/sigma/pull/304)
```
Detection:
   {'ParentImage': '*\\mshta.exe', 'Image': ['*\\cmd.exe', '*\\powershell.exe', '*\\wscript.exe', '*\\cscript.exe', '*\\sh.exe', '*\\bash.exe', '*\\reg.exe', '*\\regsvr32.exe', '*\\BITSADMIN*']}
Filter:
   {'CommandLine': ['*/HP/HP*', '*\\HP\\HP*']}
```

Rule: sigma/rules/windows/process_creation/win_wmi_spwns_powershell.yml (https://github.com/Neo23x0/sigma/pull/303)
```
Detection:
   {'Image': ['*\\powershell.exe'], 'ParentImage': ['*\\wmiprvse.exe']}
Filter:
   {'CommandLine': ['*&amp;*']}
```

Rule: sigma/rules/windows/process_creation/win_susp_powershell_enc_cmd.yml (https://github.com/Neo23x0/sigma/pull/314)
```
Condition:               selection and not 1 of falsepositive*
Filter name(s) in rule:  falsepositive*
Dangerous filters:
    Filter: falsepositive1
        Field name:     Image
              Value:       */GRR//*
    Filter: falsepositive2
        Field name:     CommandLine
              Value:       * -ExecutionPolicy remotesigned *
```              

Rule: rules/windows/process_creation/win_system_exe_anomaly.yml (https://github.com/Neo23x0/sigma/pull/323)
```
---
- sigma/rules/windows/process_creation/win_system_exe_anomaly.yml
- selection and not filter
- filter
- - filter:
    - Image:
          - '*/System32//*'
          - '*/SysWow64//*'
```

## Example

As an example the process_creation rules were scanned and the output is shown
below.

```
$ python sigmacheck.py ../sigma/rules/windows/process_creation/
---
- sigma/rules/windows/process_creation/win_attrib_hiding_files.yml
- selection and not (ini or intel)
- ini, intel
- - ini:
    - CommandLine:
      - '*/desktop.ini *'
  - intel:
    - ParentImage:
      - '*/cmd.exe'

---
- sigma/rules/windows/process_creation/win_malware_script_dropper.yml
- selection and not falsepositive
- falsepositive
- - falsepositive:
    - ParentImage:
      - '*/winzip*'

---
- sigma/rules/windows/process_creation/win_mshta_spawn_shell.yml
- selection and not filter
- filter
- - filter:
    - CommandLine:
      - '*/HP/HP*'
      - '*\HP\HP*'

---
- sigma/rules/windows/process_creation/win_plugx_susp_exe_locations.yml
- ( selection_cammute and not filter_cammute ) or ( selection_chrome_frame and not
  filter_chrome_frame ) or ( selection_devemu and not filter_devemu ) or ( selection_gadget
  and not filter_gadget ) or ( selection_hcc and not filter_hcc ) or ( selection_hkcmd
  and not filter_hkcmd ) or ( selection_mc and not filter_mc ) or ( selection_msmpeng
  and not filter_msmpeng ) or ( selection_msseces and not filter_msseces ) or ( selection_oinfo
  and not filter_oinfo ) or ( selection_oleview and not filter_oleview ) or ( selection_rc
  and not filter_rc )
- filter_cammute, filter_chrome_frame, filter_devemu, filter_gadget, filter_hcc, filter_hkcmd,
  filter_mc, filter_msmpeng, filter_msseces, filter_oinfo, filter_oleview, filter_rc
- - filter_cammute:
    - Image:
      - '*/Lenovo/Communication Utility//*'
  - filter_chrome_frame:
    - Image:
      - '*/Google/Chrome/application//*'
  - filter_devemu:
    - Image:
      - '*/Microsoft Device Emulator//*'
  - filter_gadget:
    - Image:
      - '*/Windows Media Player//*'
  - filter_hcc:
    - Image:
      - '*/HTML Help Workshop//*'
  - filter_hkcmd:
    - Image:
      - '*/System32//*'
      - '*/SysNative//*'
      - '*/SysWowo64//*'
  - filter_mc:
    - Image:
      - '*/Microsoft Visual Studio*'
      - '*/Microsoft SDK*'
      - '*/Windows Kit*'
  - filter_msmpeng:
    - Image:
      - '*/Microsoft Security Client//*'
      - '*/Windows Defender//*'
      - '*/AntiMalware//*'
  - filter_msseces:
    - Image:
      - '*/Microsoft Security Center//*'
      - '*/Microsoft Security Client//*'
      - '*/Microsoft Security Essentials//*'
  - filter_oinfo:
    - Image:
      - '*/Common Files/Microsoft Shared//*'
  - filter_oleview:
    - Image:
      - '*/Microsoft Visual Studio*'
      - '*/Microsoft SDK*'
      - '*/Windows Kit*'
      - '*/Windows Resource Kit//*'
  - filter_rc:
    - Image:
      - '*/Microsoft Visual Studio*'
      - '*/Microsoft SDK*'
      - '*/Windows Kit*'
      - '*/Windows Resource Kit//*'
      - '*/Microsoft.NET//*'

---
- sigma/rules/windows/process_creation/win_powershell_renamed_ps.yml
- all of selection and not (1 of exclusion_*)
- exclusion_*
- - exclusion_1:
    - Image:
      - '*/powershell.exe'
      - '*/powershell_ise.exe'

---
- sigma/rules/windows/process_creation/win_shell_spawn_susp_program.yml
- selection and not falsepositives
- falsepositives
- - falsepositives:
    - CurrentDirectory:
      - '*/ccmcache/*'

---
- sigma/rules/windows/process_creation/win_susp_calc.yml
- selection1 or ( selection2 and not filter2 )
- filter2
- - filter2:
    - Image:
      - '*/Windows/Sys*'

---
- sigma/rules/windows/process_creation/win_susp_control_dll_load.yml
- selection and not filter
- filter
- - filter:
    - CommandLine:
      - '*Shell32.dll*'

---
- sigma/rules/windows/process_creation/win_susp_execution_path_webserver.yml
- selection and not filter
- filter
- - filter:
    - Image:
      - '*bin//*'
      - '*/Tools//*'
      - '*/SMSComponent//*'
    - ParentImage:
      - '*/services.exe'

---
- sigma/rules/windows/process_creation/win_susp_gup.yml
- selection and not filter
- filter
- - filter:
    - Image:
      - '*/updater/*'

---
- sigma/rules/windows/process_creation/win_susp_mmc_source.yml
- selection and not exclusion
- exclusion
- - exclusion:
    - CommandLine:
      - '*/RunCmd.cmd'

---
- sigma/rules/windows/process_creation/win_susp_powershell_enc_cmd.yml
- selection and not falsepositive1
- falsepositive1
- - falsepositive1:
    - CommandLine:
      - '* -ExecutionPolicy remotesigned *'

---
- sigma/rules/windows/process_creation/win_susp_powershell_parent_combo.yml
- selection and not falsepositive
- falsepositive
- - falsepositive:
    - CurrentDirectory:
      - '*/Health Service State//*'

---
- sigma/rules/windows/process_creation/win_susp_svchost.yml
- selection and not filter
- filter
- - filter:
    - ParentImage:
      - '*/services.exe'
      - '*/MsMpEng.exe'
      - '*/Mrt.exe'

---
- sigma/rules/windows/process_creation/win_system_exe_anomaly.yml
- selection and not filter
- filter
- - filter:
    - Image:
      - '*/System32//*'
      - '*/SysWow64//*'

---
- sigma/rules/windows/process_creation/win_vul_java_remote_debugging.yml
- selection and not exclusion
- exclusion
- - exclusion:
    - - CommandLine:
        - '*address=127.0.0.1*'
    - - CommandLine:
        - '*address=localhost*'


Number of rules with wildecards in whitelist: 16
Number of rules checked:                      90
```

## Other Issues

During testing, the filter for win_susp_taskmgr_parent was found with the
following filter. Will this filter ever trigger for "Image" without wildcard?

``` bash
$ cat sigma/rules/windows/process_creation/win_susp_taskmgr_parent.yml
title: Taskmgr as Parent
status: experimental
description: Detects the creation of a process from Windows task manager
tags:
    - attack.defense_evasion
    - attack.t1036
author: Florian Roth
date: 2018/03/13
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage: '*\taskmgr.exe'
    filter:
        Image:
            - resmon.exe
            - mmc.exe
    condition: selection and not filter
fields:
    - Image
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative activity
level: low
```

## Credits
Thanks to [strfx](https://github.com/strfx) and [droe](https://github.com/droe) for inputs and discussion.
