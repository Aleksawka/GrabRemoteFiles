#! /usr/bin/python3
import base64
import concurrent
import functools
import sys
from concurrent.futures import wait
from concurrent.futures.thread import ThreadPoolExecutor

import paramiko
import argparse
import logging
import re
import errno
import os
import stat
from collections import defaultdict
from paramiko.client import AutoAddPolicy
import time
import posixpath

host_path_regex = r"(.{1,})\|(.{1,})"

parser = argparse.ArgumentParser()
parser.add_argument('paths', action='store')

logging.basicConfig(filename='grab.log', level=logging.INFO, format="%(thread)d:%(message)s")

user = base64.b64decode(os.getenv("GRAB_USER"))
password = base64.b64decode(os.getenv("GRAB_PWD"))


# validate paths variable
def validate_param(path_arg: str):
    grab_paths = defaultdict(set)
    if not path_arg:
        return False, grab_paths

    host_path_pairs = path_arg.split(',')
    if not host_path_pairs:
        return False, grab_paths

    for host_path_pair in host_path_pairs:
        match = re.search(host_path_regex, host_path_pair)
        if not match:
            return False, grab_paths
        else:
            host = match.group(1)
            host_path = match.group(2)
            grab_paths[host].add(host_path)
    return True, grab_paths


def grab_files(host: str, paths: set):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    try:
        logging.info("Connect to {}".format(host))
        client.connect(hostname=host, username=user, password=password, timeout=10)
        logging.info("Connected to {}".format(host))
        sftp = client.open_sftp()
        for remote_path in paths:
            download_files(sftp, host, remote_path, host)
    except Exception as e:
        logging.exception("Connect to {} failed, caught exception:".format(host))
        return
    finally:
        try:
            client.close()
            logging.info("Connection to {} closed".format(host))
        except Exception:
            pass


def download_files(sftp_client, remote_host, remote_dir, local_dir):
    try:
        if not exists_remote(sftp_client, remote_host, remote_dir):
            return

        if not os.path.exists(local_dir):
            os.mkdir(local_dir)

        for fileattr in sftp_client.listdir_attr(remote_dir):
            file_path = posixpath.join(remote_dir, fileattr.filename)
            if stat.S_ISDIR(fileattr.st_mode):
                download_files(sftp_client, remote_host, file_path,
                               os.path.join(local_dir, fileattr.filename))
            else:
                try:
                    def download_callback(bytes_so_far, bytes_total):
                        logging.info('Transfer of %r from %r is at %d/%d bytes (%.1f%%)' % (
                            file_path, remote_host, bytes_so_far, bytes_total, 100. * bytes_so_far / bytes_total))

                    logging.info("Grab file {} from {} started".format(remote_host, file_path))
                    sftp_client.get(file_path, posixpath.join(local_dir, fileattr.filename),
                                    callback=download_callback)
                    logging.info("Grab file {} from {} finished".format(remote_host, file_path))
                except Exception as e:
                    logging.exception("Grab from {} path {} failed, caught exception:".format(remote_host, file_path))
    except Exception as e:
        logging.exception("Grab from {} path {} failed, caught exception:".format(remote_host, remote_dir))


def exists_remote(sftp_client, remote_host, path):
    try:
        sftp_client.stat(path)
    except IOError as e:
        if e.errno == errno.ENOENT:
            logging.error("Path {} on {} doesn't exist".format(remote_host, path))
            return False
    else:
        return True


if __name__ == '__main__':
    st = time.time()

    args = parser.parse_args()
    if not args.paths:
        logging.error("Provide parameter for grabbing")
        sys.exit(-1)
    paths = sys.argv[1]
    (isValid, grab_files_paths) = validate_param(paths)
    if not isValid:
        logging.error("Invalid parameter for grabbing: check format of <host>|<path> pairs.")
        sys.exit(-1)

    nthreads = len(grab_files_paths.items())

    with ThreadPoolExecutor(nthreads) as executor:
        futures = [executor.submit(grab_files, host, host_paths) for host, host_paths in grab_files_paths.items()]
        done, not_done = wait(futures, return_when=concurrent.futures.ALL_COMPLETED)

    et = time.time()
    elapsed_time = (et - st)
    logging.info(msg='Execution time: {} seconds'.format(elapsed_time))
    sys.exit(0)
