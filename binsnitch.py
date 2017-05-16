import subprocess
import time
import argparse
import hashlib
import json
import logging
import os
import signal
import traceback

# Status Constants
import sys

FILE_KNOWN_UNTOUCHED = "FILE_KNOWN_UNTOUCHED"
FILE_KNOWN_TOUCHED = "FILE_KNOWN_TOUCHED"
FILE_UNKNOWN = "FILE_UNKNOWN"

# List of dangerous file extensions
dangerous_extensions = set(["DMG","DLL", "ACTION","APK","APP","BAT","BIN","CMD","COM","COMMAND","CPL","CSH","EXE","GADGET","INF1","INS","INX","IPA","ISU","JOB","JSE","KSH","LNK","MSC","MSI","MSP","MST","OSX","OUT","PAF","PIF","PRG","PS1","REG","RGS","RUN","SCT","SH","SHB","SHS","U3P","VB","VBE","VBS","VBSCRIPT","WORKFLOW","WS","WSF"])

# Global variables
cached_db = None

###########
#Utilities#
###########
def shellquote(s):
    return "'" + s.replace("'", "'\\''") + "'"


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


def check_file_status(file_info):
    global cached_db

    known_path = False

    for db_file in cached_db:
        if db_file["path"] == file_info["path"]:
            known_path = True

            if file_info["sha256"] in db_file["sha256"]:
                return FILE_KNOWN_UNTOUCHED
            else:
                return FILE_KNOWN_TOUCHED

    if not known_path:
        return FILE_UNKNOWN


def add_alert_do_db(file_info, status):
    global cached_db

    with open("binsnitch_data/db.json") as data_file:
        db_data = json.load(data_file)

    for db_file in db_data:
        if db_file["path"] == file_info["path"]:
            if file_info["sha256"] not in db_file["sha256"]:
                db_file["sha256"].append(file_info["sha256"])

            if status == FILE_UNKNOWN:
                logging.info("New file detected: " + db_file["path"] + " - hash: " + file_info["sha256"])

            if status == FILE_KNOWN_TOUCHED:
                logging.info("Modified file detected: " + db_file["path"] + " - new hash: " + file_info["sha256"])

    cached_db = db_data
    write_to_db(cached_db)


def write_to_db(db_data):
    s = signal.signal(signal.SIGINT, signal.SIG_IGN)
    json.dump(db_data, open("binsnitch_data/db.json", 'w'), sort_keys=False, indent=4, separators=(',', ': '))
    signal.signal(signal.SIGINT, s)


def add_file_to_db(file_info):
    global cached_db

    with open("binsnitch_data/db.json") as data_file:
        db_data = json.load(data_file)

    file_info_to_add = {"path": file_info["path"], "sha256": [file_info["sha256"]]}

    db_data.append(file_info_to_add)
    cached_db = db_data
    write_to_db(cached_db)


def refresh_cache():
    global cached_db
    try:
        file = open("binsnitch_data/db.json", 'r')
        cached_db = json.load(file)
    except Exception as exc:
        print(str(sys.exc_info()))


def prepare_data_files(args):
    global cached_db

    # Wipe both alerts and db file in case the user wants to start fresh
    try:
        if args.wipe:
            os.remove("binsnitch_data/db.json")
            os.remove("binsnitch_data/alerts.log")
    except IOError:
        pass # if the files are not there yet, then the wipe does not do anything anyway

    # Make sure the data folders exist
    if not os.path.exists("./binsnitch_data"):
        os.makedirs("./binsnitch_data")

    try:
        file = open("binsnitch_data/db.json", 'r')
    except IOError:
        json.dump([], open("binsnitch_data/db.json", 'w'))

    try:
        file = open("binsnitch_data/alerts.log", 'r')
    except IOError:
        open("binsnitch_data/alerts.log", 'a').close()

    refresh_cache()

############
#Entrypoint#
############
parser = argparse.ArgumentParser()
parser.add_argument("dir", type=str, help="the directory to monitor")
parser.add_argument("-v", "--verbose", action="store_true", help="increase output verbosity")
parser.add_argument("-s", "--singlepass", action="store_true", help="do a single pass over all files")
parser.add_argument("-a", "--all", action="store_true", help="keep track of all files, not only executables")
parser.add_argument("-n", "--new", action="store_true", help="alert on new files too, not only on modified files")
parser.add_argument("-b", "--baseline", action="store_true", help="do not generate alerts (useful to create baseline)")
parser.add_argument("-w", "--wipe", action="store_true", help="start with a clean db.json and alerts.log file")

args = parser.parse_args()
prepare_data_files(args)

logging.basicConfig(format = '%(asctime)s - %(levelname)s - %(message)s',
                    datefmt = '%m/%d/%Y %I:%M:%S %p',
                    filename = "binsnitch_data/alerts.log",
                    level=logging.INFO)
logging.getLogger().addHandler(logging.StreamHandler())

logging.info("binsnitch.py started")

if not os.path.isdir(args.dir):
    print("Error: " + args.dir + " could not be read, exiting.")
    exit()

print("Loaded " + str(len(cached_db)) + " items from db.json into cache")

keepRunning = True
while keepRunning:
    logging.info("Scanning system for new and modified files, this can take a long time")

    for dirName, subdirList, fileList in os.walk(args.dir, topdown=False):
        try:
            if args.verbose:
                print('Scanning %s' % dirName)
        except UnicodeEncodeError as e:
            continue

        for filename in fileList:
            full_path = os.path.join(dirName, filename)
            file_extension = str.upper(os.path.splitext(full_path)[1][1:])

            try:
                process_file = False

                if args.all:
                    process_file = True
                else:
                    if file_extension in dangerous_extensions:
                        process_file = True

                if process_file:
                    file_hash = sha256_checksum(full_path)

                    file_info = dict()
                    file_info["path"] = full_path
                    file_info["sha256"] = file_hash

                    status = check_file_status(file_info)

                    if status == FILE_UNKNOWN:
                        add_file_to_db(file_info)

                        if args.new and not args.baseline:
                            add_alert_do_db(file_info, FILE_UNKNOWN)

                    elif status == FILE_KNOWN_TOUCHED:
                        if not args.baseline:
                            add_alert_do_db(file_info, FILE_KNOWN_TOUCHED)

                    elif status == FILE_KNOWN_UNTOUCHED:
                        pass

            except Exception as exc:
                print(str(sys.exc_info()))

    if not args.singlepass:
        logging.info("Finished! Sleeping for a minute before scanning " + args.dir + " for changes again")
        time.sleep(60)
    else:
        logging.info("Finished!")
        keepRunning = False
