
# MIT License
# (C) Copyright [2021] Hewlett Packard Enterprise Development LP
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
# THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

import datetime
import io
import logging
import os
import threading

import boto3
import kubernetes.client
import kubernetes.config
import kubernetes.stream
import yaml


def fetch_secrets_yaml(ks_core_v1, name, namespace):
    secret = ks_core_v1.read_namespaced_secret(name, namespace)
    res = {
        'apiVersion': secret.api_version,
        'kind': secret.kind,
        'type': secret.type,
        'metadata': {
            'name': secret.metadata.name,
            'namespace': secret.metadata.namespace,
            'labels': secret.metadata.labels,
        },
        'data': secret.data,
    }
    return yaml.dump(res)


def read_pgdump_output(pgdump_stream, f):
    total_stdout_bytes = 0

    while pgdump_stream.is_open():
        pgdump_stream.update(timeout=1)
        any_output = False
        if pgdump_stream.peek_stdout():
            s = pgdump_stream.read_stdout()
            bytes_read = len(s)
            total_stdout_bytes = total_stdout_bytes + bytes_read
            logging.info("Read %s from stdout (%s total)", bytes_read, total_stdout_bytes)
            f.write(bytes(s, encoding='utf-8'))
            any_output = True
        if pgdump_stream.peek_stderr():
            s = pgdump_stream.read_stderr()
            logging.warn("Output on stderr: %s", s)
            any_output = True
        if not any_output:
            logging.info("Nothing in stout/stderr.")
    pgdump_stream.close()
    logging.info("Closed pg_dumpall stream, read %s bytes from pg_dumpall", total_stdout_bytes)
    f.close()


def upload_fileobj_cb(count):
    logging.info("progress: upload_fileobj sent %s bytes.", count)


def calc_key_base(db_name):
    # The key base is made up of the db_name and a timestamp.
    timestamp = datetime.datetime.utcnow().isoformat(timespec='seconds')
    return f'{db_name}-{timestamp}'


def get_keys_for_db(stg_client, bucket, db_name):
    prefix = f'{db_name}-'
    logging.info("Listing objects in %r with prefix %r", bucket, prefix)
    res = stg_client.list_objects(Bucket=bucket, Prefix=prefix)
    keys = [x['Key'] for x in res['Contents']]
    logging.info("Keys for db %r: %s", db_name, keys)
    return keys


def calc_timestamp(db_name, key):
    # Extracts the timestamp from the key.
    # The key is like <db_name>-<timestamp>.<suffix>.
    key = key[len(db_name)+1:]
    key = key.rsplit('.', 1)[0]
    return key


def calc_timestamps(db_name, keys):
    # Given a list of keys, returns a sorted list of unique timestamps from the
    # keys.
    timestamps = list({calc_timestamp(db_name, k) for k in keys})
    timestamps.sort()
    return timestamps


def get_backup_timestamps(stg_client, bucket, db_name):
    # Returns a sorted list of the timestamps for the backups for the DB.
    keys = get_keys_for_db(stg_client, bucket, db_name)
    timestamps = calc_timestamps(db_name, keys)
    return (keys, timestamps)


def calc_timestamps_to_delete(backup_timestamps):
    # Just keeping the most recent backup.
    return backup_timestamps[:-1]


def delete_backups(stg_client, bucket, db_name, keys, timestamps_to_delete):
    logging.info("Deleting backups with timestamps %s", timestamps_to_delete)
    for k in keys:
        k_ts = calc_timestamp(db_name, k)
        if k_ts in timestamps_to_delete:
            logging.info("Deleting %r", k)
            stg_client.delete_object(Bucket=bucket, Key=k)


def cleanup_old_backups(stg_client, bucket, db_name):
    keys, backup_timestamps = get_backup_timestamps(stg_client, bucket, db_name)
    timestamps_to_delete = calc_timestamps_to_delete(backup_timestamps)
    delete_backups(stg_client, bucket, db_name, keys, timestamps_to_delete)


def postgres_db_backup(db_name, namespace, bucket):
    ks_core_v1 = kubernetes.client.CoreV1Api()
    logging.info("Connected to k8s")

    # FIXME: need to get the leader instance and exec from there.
    pod_name = f'{db_name}-0'
    container_name = 'postgres'
    logging.info(
        "Exec'ing pg_dumpall on -n %s -c %s %s...", namespace, container_name, pod_name)
    exec_command = [
        'pg_dumpall',
        '-U', 'postgres',
        '-c',
    ]
    pgdump_stream = kubernetes.stream.stream(
        ks_core_v1.connect_get_namespaced_pod_exec,
        pod_name,
        namespace,
        container=container_name,
        command=exec_command,
        stderr=True, stdin=False,
        stdout=True, tty=False,
        _preload_content=False)

    (read_fd, write_fd) = os.pipe()

    f_read = os.fdopen(read_fd, 'rb')
    f_write = os.fdopen(write_fd, 'wb')

    t = threading.Thread(
        target=read_pgdump_output, args=(pgdump_stream, f_write,))
    t.start()

    stg_endpoint = os.environ['STORAGE_ENDPOINT']
    stg_tls_verify = (os.environ['STORAGE_TLS_VERIFY'].lower() == 'true')
    stg_acces_key = os.environ['STORAGE_ACCESS_KEY']
    stg_secret_key = os.environ['STORAGE_SECRET_KEY']

    key_base = calc_key_base(db_name)

    pgdump_key = f'{key_base}.psql'
    logging.info(
        "Sending pg_dump file to storage. endpoint=%s, access_key=%s, bucket=%r, key=%r",
        stg_endpoint, stg_acces_key, bucket, pgdump_key)

    stg_client = boto3.client(
        's3',
        endpoint_url=stg_endpoint,
        verify=stg_tls_verify,
        aws_access_key_id=stg_acces_key,
        aws_secret_access_key=stg_secret_key)

    # FIXME: any attributes to set on the file?
    stg_client.upload_fileobj(f_read, bucket, pgdump_key, Callback=upload_fileobj_cb)
    logging.info("Completed sending pg_dump file to storage.")

    t.join()
    f_read.close()

    sa_creds = fetch_secrets_yaml(
        ks_core_v1, f'service-account.{db_name}.credentials', namespace)
    pg_creds = fetch_secrets_yaml(
        ks_core_v1, f'postgres.{db_name}.credentials', namespace)
    standby_creds = fetch_secrets_yaml(
        ks_core_v1, f'standby.{db_name}.credentials', namespace)

    creds_contents = f'''
---
{sa_creds}

---
{pg_creds}

---
{standby_creds}
'''

    creds_key = f'{key_base}.manifest'
    stg_client.upload_fileobj(
        io.BytesIO(creds_contents.encode('utf-8')), bucket, creds_key)
    logging.info("Completed sending creds file to storage. key=%r", creds_key)

    cleanup_old_backups(stg_client, bucket, db_name)


def main():
    # Configure logging
    log_format = '%(asctime)-15s - %(levelname)-7s - %(name)s - %(message)s'
    logging.basicConfig(level=logging.INFO, format=log_format)

    # Load K8s configuration
    kubernetes.config.load_incluster_config()

    db_name = os.environ['DB_NAME']
    namespace = os.environ['NAMESPACE']
    bucket = os.environ['STORAGE_BUCKET']

    postgres_db_backup(db_name, namespace, bucket)


if __name__ == '__main__':
    main()
