# binsnitch.py
binsnitch can be used to detect silent unwanted changes to files on your system.
It will scan a given directory recursively for files and keep track of any changes it detects, based on the SHA256 hash of the file.
You have the option to either track executable files, or all files.

### Requirements
- python 3

### Running and usage
```
usage: binsnitch.py [-h] [-v] [-s] [-a] [-n] [-b] [-w] dir

positional arguments:
  dir               the directory to monitor

optional arguments:
  -h, --help        show this help message and exit
  -v, --verbose     increase output verbosity
  -s, --singlepass  do a single pass over all files
  -a, --all         keep track of all files, not only executables
  -n, --new         alert on new files too, not only on modified files
  -b, --baseline    do not generate alerts (useful to create baseline)
  -w, --wipe        start with a clean db.json and alerts.log file
```

Example: monitor all executable files on the system and enable verbose logging

```
python3.5 binsnitch.py -v / 
```

Example: monitor all files in the current directory and enable verbose logging

```
python3.5 binsnitch.py -v -a . 
```

### How it works
Once ``binsnitch.py`` is running, it will scan all files in ``dir`` (provided through a required command line argument) recursively, and create a SHA256 hash of each file it finds. It then does the following:
- If a file is not known yet by ``binsnitch.py``, its details will be added to ``binsnitch_data/db.json`` (file name, file type and hash).
- If a file is already known but the calculated hash is different from the one in ``binsnitch_data/db.json``, an alert will be logged to ``data/alert.log``. In addition, the new hash will be added to the appropriate entry in ``binsnitch_data/db.json``.
- If a file is already known and the hash is identical to the one already in ``binsnitch_data/alert.log``, nothing happens.

### Example output

##### binsnitch_data/alerts.log
```
05/15/2017 02:46:17 AM - INFO - Scanning system for new and modified files, this can take a long time
05/15/2017 02:53:38 AM - INFO - Modified file detected: /Applications/Cyberduck.app/Contents/Frameworks/Sparkle.framework/Versions/A/Resources/Autoupdate.app/Contents/MacOS/Autoupdate - new hash: a897613ab9ecd8ead7b697012036b2ef683a9df7afe99d9013e5dd6c3e08af10
05/15/2017 02:53:39 AM - INFO - Modified file detected: /Applications/Cyberduck.app/Contents/Frameworks/Sparkle.framework/Versions/A/Resources/Autoupdate.app/Contents/MacOS/fileop - new hash: cdad8d7b1cce37547223a198e9fbbe256aed3919b58e1b2305870aeaac33c966
05/15/2017 02:53:41 AM - INFO - Modified file detected: /Applications/Cyberduck.app/Contents/MacOS/Cyberduck - new hash: 3941de0b9001c616c6fcfdb76108fa5da46bdcdd3089e1feb65578c2d251eeec
```

##### binsnitch_data/db.json

```
[
    {
        "path": "/Applications/1Password 6.app/Contents/Frameworks/AgileLibrary.framework/Versions/A/Resources/pngquant",
        "sha256": [
            "47ecd7d9978a291de70aaf5e4392664d5c697cd0867bb59f3d6833671b83d448"
        ],
        "type": "Mach-O 64-bit executable x86_64"
    }
]
```

### Internals
Checking if a file is executable is done by checking it against a fixed list of dangerous file extensions (check ``binsnitch.py`` source for details).

In its current version, ``binsnitch.py`` eats up a lot of CPU. This is caused by the recursive walk through the filesystem and the calculation of SHA256 hashes for each and every file it encounters.

### Ideas for improvement

- ~~Include a switch to start with a new alerts and db file upon start~~ ☑
- ~~Include a switch to also process new files~~ ☑
- ~~Enable a switch to process all files instead of executables only~~ ☑
- ~~Include a switch for a single pass instead of running forever~~ ☑
- ~~Remove dependency on ``file`` command to check for file type information~~ ☑
- Be nicer to system resources (IO and CPU)

### Why binsnitch?

Malware will often settle itself by overwriting existing executable applications in order to avoid detection.
Recent malware cases (May 2017) do this, including HandBrake being hacked to drop new variant of the Proton malware and the WannaCry ransomware overwriting ``C:\WINDOWS\system32\tasksche.exe``.
This triggered us to write a simple tool that could be used to detect this.

binsnitch can also be used during malware analysis, to detect silent changes to files (i.e. replacement of a trusted Windows executable by a trojaned version).

### References and comparison to other tools

Similar tools:
- Microsoft File Checksum Integrity Verifier - https://www.microsoft.com/en-us/download/details.aspx?id=11533
- Syscheck in OSSEC - http://ossec-docs.readthedocs.io/en/latest/manual/syscheck/

These tools are either OS-dependent or require installation of libraries. In addition, ``binsnitch.py`` can be used to detect changes to the file system after an infection has taken place  (not depending on intercepting API calls during the infection itself) - for example, when analyzing a disk image against a "known good" baseline.

``binsnitch.py`` aims at being dependent on core packages available in ``python`` only.

### Community

Bug reports and feature requests are welcome in the issues tab!

Contact us: research@nviso.be.

binsnitch is developed and maintained by Daan Raman ([@daanraman](https://twitter.com/daanraman)).

