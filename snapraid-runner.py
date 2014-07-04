# -*- coding: utf8 -*-
import argparse
import ConfigParser
import logging
import logging.handlers
import os.path
import subprocess
import sys
import threading
import time
import traceback
from collections import Counter, defaultdict
from cStringIO import StringIO

# Global variables
config = None
email_log = None


def tee_log(infile, out_lines, log_level):
    """
    Create a thread that saves all the output on infile to out_lines and
    logs every line with log_level
    """
    def tee_thread():
        for line in iter(infile.readline, ""):
            line = line.strip()
            # Do not log the progress display
            if "\r" in line:
                line = line.split("\r")[-1]
            logging.log(log_level, line.strip())
            out_lines.append(line)
        infile.close()
    t = threading.Thread(target=tee_thread)
    t.daemon = True
    t.start()
    return t


def snapraid_command(command, args={}):
    """
    Run snapraid command
    Raises subprocess.CalledProcessError if errorlevel != 0
    """
    arguments = ["--conf", config["snapraid"]["config"]]
    for (k, v) in args.items():
        arguments.extend(["--" + k, str(v)])
    p = subprocess.Popen(
        [config["snapraid"]["executable"], command] + arguments,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    out = []
    threads = [
        tee_log(p.stdout, out, logging.OUTPUT),
        tee_log(p.stderr, [], logging.OUTERR)]
    for t in threads:
        t.join()
    ret = p.wait()
    # sleep for a while to make pervent output mixup
    time.sleep(0.3)
    if ret == 0:
        return out
    else:
        raise subprocess.CalledProcessError(ret, "snapraid " + command)

def execute_command(command, args={}, display=False):
    p = subprocess.Popen([command] + args,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    out = []
    if ( display ):
        threads = [
            tee_log(p.stdout, out, logging.OUTPUT),
            tee_log(p.stderr, [], logging.OUTERR)]
        for t in threads:
            t.join()
    else:
        (out,err) = p.communicate()
        out = out.splitlines()
    ret = p.wait()
    time.sleep(0.3)
    if ret == 0:
        return out
    else:
        raise subprocess.CalledProcessError(ret, command)

def send_email(success):
    import smtplib
    from email.mime.text import MIMEText
    from email import charset

    if len(config["smtp"]["host"]) == 0:
        logging.error("Failed to send email because smtp host is not set")
        return

    # use quoted-printable instead of the default base64
    charset.add_charset("utf-8", charset.SHORTEST, charset.QP)
    if success:
        body = "SnapRAID job completed successfully:\n\n\n"
    else:
        body = "Error during SnapRAID job:\n\n\n"
    body += email_log.getvalue()
    msg = MIMEText(body, "plain", "utf-8")
    msg["Subject"] = config["email"]["subject"] + \
        (" SUCCESS" if success else " ERROR")
    msg["From"] = config["email"]["from"]
    msg["To"] = config["email"]["to"]
    smtp = {"host": config["smtp"]["host"]}
    if config["smtp"]["port"]:
        smtp["port"] = config["smtp"]["port"]
    if config["smtp"]["ssl"]:
        server = smtplib.SMTP_SSL(**smtp)
    else:
        server = smtplib.SMTP(**smtp)
    if config["smtp"]["user"]:
        server.login(config["smtp"]["user"], config["smtp"]["password"])
    server.sendmail(
        config["email"]["from"],
        [config["email"]["to"]],
        msg.as_string())
    server.quit()


def finish(is_success):
    if ("error", "success")[is_success] in config["email"]["sendon"]:
        try:
            send_email(is_success)
        except:
            logging.exception("Failed to send email")
    if is_success:
        logging.info("Run finished successfully")
    else:
        logging.error("Run failed")
    sys.exit(0 if is_success else 1)


def load_config(args):
    global config
    parser = ConfigParser.RawConfigParser()
    parser.read(args.conf)
    sections = ["snapraid", "logging", "email", "smtp", "scrub", "install", "uninstall"]
    config = dict((x, defaultdict(lambda: "")) for x in sections)
    for section in parser.sections():
        for (k, v) in parser.items(section):
            config[section][k] = v.strip()

    int_options = [
        ("snapraid", "deletethreshold"), ("logging", "maxsize"),
        ("scrub", "percentage"), ("scrub", "older-than")
    ]
    for section, option in int_options:
        try:
            config[section][option] = int(config[section][option])
        except ValueError:
            config[section][option] = 0

    config["smtp"]["ssl"] = (config["smtp"]["ssl"].lower() == "true")
    config["scrub"]["enabled"] = (config["scrub"]["enabled"].lower() == "true")
    config["email"]["short"] = (config["email"]["short"].lower() == "true")

    if args.scrub is not None:
        config["scrub"]["enabled"] = args.scrub

    if args.install is not None:
        config["install"]["enabled"] = args.install

    if args.uninstall is not None:
        config["uninstall"]["enabled"] = args.uninstall

def setup_logger():
    log_format = logging.Formatter(
        "%(asctime)s [%(levelname)-6.6s] %(message)s")
    root_logger = logging.getLogger()
    logging.OUTPUT = 15
    logging.addLevelName(logging.OUTPUT, "OUTPUT")
    logging.OUTERR = 25
    logging.addLevelName(logging.OUTERR, "OUTERR")
    root_logger.setLevel(logging.OUTPUT)
    console_logger = logging.StreamHandler(sys.stdout)
    console_logger.setFormatter(log_format)
    root_logger.addHandler(console_logger)

    if config["logging"]["file"]:
        max_log_size = min(config["logging"]["maxsize"], 0) * 1024
        file_logger = logging.handlers.RotatingFileHandler(
            config["logging"]["file"],
            maxBytes=max_log_size,
            backupCount=9)
        file_logger.setFormatter(log_format)
        root_logger.addHandler(file_logger)

    if config["email"]["sendon"]:
        global email_log
        email_log = StringIO()
        email_logger = logging.StreamHandler(email_log)
        email_logger.setFormatter(log_format)
        if config["email"]["short"]:
            # Don't send programm stdout in email
            email_logger.setLevel(logging.INFO)
        root_logger.addHandler(email_logger)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--conf",
                        default="snapraid-runner.conf",
                        metavar="CONFIG",
                        help="Configuration file (default: %(default)s)")
    parser.add_argument("--no-scrub", action='store_false',
                        dest='scrub', default=None,
                        help="Do not scrub (overrides config)")
    parser.add_argument("--install", action='store_true',
                        dest='install', default=None,
                        help="Install script to crontab")
    parser.add_argument("--uninstall", action='store_true',
                        dest='uninstall', default=None,
                        help="Remove script from crontab")
    args = parser.parse_args()

    if not os.path.exists(args.conf):
        print("snapraid-runner configuration file not found")
        parser.print_help()
        sys.exit(2)

    try:
        load_config(args)
    except:
        print("unexpected exception while loading config")
        print traceback.format_exc()
        sys.exit(2)

    try:
        setup_logger()
    except:
        print("unexpected exception while setting up logging")
        print traceback.format_exc()
        sys.exit(2)

    try:
        init()
    except Exception:
        logging.exception("init failed due to unexpected exception:")
        finish(False)

def install():
    logging.info("=" * 60)
    logging.info("Starting install process...")
    logging.info("=" * 60)
    logging.info("Loading current crontab contents")
    out = execute_command("crontab",["-l"])
    runnerFile = os.path.basename(__file__)
    runnerFilePath = os.path.realpath(__file__)
    contents = '\n'.join(out)
    logging.info("Processing crontab contents")
    if runnerFile in contents:
        logging.info("Script ( " + runnerFile + " ) already installed, nothing to do")
    else:
        contents += "\n@daily python " + runnerFilePath + "\n"
        tmpFile = "/tmp/snapraid-runner.tmpRfgyU"
        afile = open(tmpFile,"w")
        afile.write(contents)
        afile.close()
        logging.info("Installing new crontab")
        execute_command("crontab",[tmpFile])

    logging.info("=" * 60)
    logging.info("Finished install process...")
    logging.info("=" * 60)

def uninstall():
    logging.info("=" * 60)
    logging.info("Starting uninstall process...")
    logging.info("=" * 60)

    logging.info("Loading current crontab contents")
    out = execute_command("crontab",["-l"])
    runnerFile = os.path.basename(__file__)
    runnerFilePath = os.path.realpath(__file__)
    contents = '\n'.join(out)

    logging.info("Processing crontab contents")
    if runnerFile in contents:
        tmpFile = "/tmp/snapraid-runner.tmpRfgyU"
        afile = open(tmpFile,"w")
        for item in out:
            if runnerFile not in item:
                afile.write("%s\n" % item)
        afile.close()
        logging.info("Installing new crontab")
        execute_command("crontab",[tmpFile])
    else:
        logging.info("Script ( " + runnerFile + " ) not present, nothing to do")

    logging.info("=" * 60)
    logging.info("Finished uninstall process...")
    logging.info("=" * 60)

def init():
    if not os.path.isfile(config["snapraid"]["executable"]):
        logging.error("The configured snapraid executable \"{}\" does not "
                      "exist or is not a file".format(
                          config["snapraid"]["executable"]))
        finish(False)
    if not os.path.isfile(config["snapraid"]["config"]):
        logging.error("Snapraid config does not exist at " +
                      config["snapraid"]["config"])
        finish(False)

    if config["install"]["enabled"]:
        install()
        sys.exit(0)

    if config["uninstall"]["enabled"]:
        uninstall()
        sys.exit(0)

    """
       Neither install or uninstall enabled perform run
    """
    run()

def run():
    logging.info("=" * 60)
    logging.info("Run started")
    logging.info("=" * 60)

    logging.info("Running diff...")
    try:
        diff_out = snapraid_command("diff")
    except subprocess.CalledProcessError as e:
        logging.error(e)
        finish(False)
    logging.info("*" * 60)

    diff_results = Counter(line.split(" ")[0] for line in diff_out)
    diff_results = dict((x, diff_results[x]) for x in
                        ["add", "remove", "move", "update"])
    logging.info(("Diff results: {add} added,  {remove} removed,  "
                  + "{move} moved,  {update} modified").format(**diff_results))

    if (config["snapraid"]["deletethreshold"] >= 0 and
            diff_results["remove"] > config["snapraid"]["deletethreshold"]):
        logging.error(
            "Deleted files exceed delete threshold of {}, aborting".format(
            config["snapraid"]["deletethreshold"]))
        finish(False)

    if (diff_results["remove"] + diff_results["add"] + diff_results["move"] +
            diff_results["update"] == 0):
        logging.info("No changes detected, no sync required")
    else:
        logging.info("Running sync...")
        try:
            snapraid_command("sync")
        except subprocess.CalledProcessError as e:
            logging.error(e)
            finish(False)
        logging.info("*" * 60)

    if config["scrub"]["enabled"]:
        logging.info("Running scrub...")
        try:
            snapraid_command("scrub", {
                "percentage": config["scrub"]["percentage"],
                "older-than": config["scrub"]["older-than"],
            })
        except subprocess.CalledProcessError as e:
            logging.error(e)
            finish(False)
        logging.info("*" * 60)

    """   Perform status check for email """
    logging.info("Running status...")
    try:
        snapraid_command("status")
    except subprocess.CalledProcessError as e:
        logging.error(e)
        finish(False)

    logging.info("=" * 60)
    logging.info("Run complete")
    logging.info("=" * 60)
    finish(True)


main()
