
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
import json
import logging
import os
import subprocess

import boto3
import kubernetes.client
import kubernetes.config
import kubernetes.stream
import psycopg2
import yaml


def query_replicas(pg_host, pg_port, pg_database, pg_user, pg_password):
    logging.info("Connecting to database...")
    with psycopg2.connect(
            dbname=pg_database, user=pg_user, password=pg_password,
            host=pg_host, port=pg_port) as conn:
        with conn.cursor() as curs:
            # This should be a small result set so just fetch them all,
            # then the result can be logged to help debugging.
            # Notes that the pg_stat_replication view only contains the
            # slots/replicas that are currently working.
            sql = (
                "SELECT application_name, pg_current_wal_lsn() - replay_lsn AS behind"
                " FROM pg_stat_replication"
                " WHERE state='streaming'")
            curs.execute(sql)
            res = curs.fetchall()
            logging.info("res = %s", res)

    if not res:
        # There's no replicas.
        return None

    # This sorts the result by how far behind the replica is.
    res.sort(key=lambda r: r[1])
    # Check if the closest replica is close enough.
    if res[0][1] < (1024 * 1024):
        return res[0][0]
    # Otherwise the closest replica is too far out of sync.


def select_target_pg_host(pg_host, pg_port, pg_database, pg_user, pg_password):
    target_replica = query_replicas(pg_host, pg_port, pg_database, pg_user, pg_password)
    if target_replica:
        logging.info("Target replica is %r", target_replica)
        return target_replica
    logging.info("No target replica so using pg_host %r", pg_host)
    return pg_host


def pg_dump_to_storage(target_host, key_base, stg_client, bucket):
    cmd = ['pg_dumpall', '-c', '-h', target_host]
    logging.info("Exec'ing %r", cmd)

    pg_dumpall_subprocess = subprocess.Popen(cmd, stdout=subprocess.PIPE)

    pgdump_key = f'{key_base}.psql'
    logging.info(
        "Sending pg_dump file to storage. bucket=%r, key=%r", bucket, pgdump_key)

    stg_client.upload_fileobj(
        pg_dumpall_subprocess.stdout, bucket, pgdump_key,
        Callback=upload_fileobj_cb)

    logging.info("Completed sending pg_dump file to storage.")

    pg_dumpall_subprocess.wait()

    if pg_dumpall_subprocess.returncode != 0:
        logging.error("pg_dumpall exit status is %s", pg_dumpall_subprocess.returncode)
        raise Exception("pg_dumpall command failed.")


def fetch_secrets_yaml(ks_core_v1, name, namespace):
    logging.info("Fetching %s/%s secrets", namespace, name)
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


def user_name_to_secret_name(user_name):
    return user_name.replace('_', '-')


def k8s_objects_to_storage(db_name, users, namespace, stg_client, bucket, key_base):
    ks_core_v1 = kubernetes.client.CoreV1Api()
    objs = []
    for u in users:
        secret_name = user_name_to_secret_name(u)
        objs.append(fetch_secrets_yaml(
            ks_core_v1, f'{secret_name}.{db_name}.credentials', namespace))
    objs.append(fetch_secrets_yaml(
        ks_core_v1, f'postgres.{db_name}.credentials', namespace))
    objs.append(fetch_secrets_yaml(
        ks_core_v1, f'standby.{db_name}.credentials', namespace))

    creds_contents = ''
    for o in objs:
        s = f'''
---
{o}
'''
        creds_contents += s

    creds_key = f'{key_base}.manifest'
    stg_client.upload_fileobj(
        io.BytesIO(creds_contents.encode('utf-8')), bucket, creds_key)
    logging.info("Completed sending creds file to storage. key=%r", creds_key)


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


def postgres_db_backup(
        db_name, users, namespace, bucket,
        pg_host, pg_port, pg_database, pg_user, pg_password,
        stg_endpoint, stg_tls_verify, stg_acces_key, stg_secret_key):

    target_pg_host = select_target_pg_host(
        pg_host, pg_port, pg_database, pg_user, pg_password)

    logging.info(
        "Initializing storage client. endpoint=%s access_key=%s",
        stg_endpoint, stg_acces_key)

    stg_client = boto3.client(
        's3',
        endpoint_url=stg_endpoint,
        verify=stg_tls_verify,
        aws_access_key_id=stg_acces_key,
        aws_secret_access_key=stg_secret_key)

    key_base = calc_key_base(db_name)

    pg_dump_to_storage(target_pg_host, key_base, stg_client, bucket)
    k8s_objects_to_storage(db_name, users, namespace, stg_client, bucket, key_base)
    cleanup_old_backups(stg_client, bucket, db_name)


def main():
    # Configure logging
    log_format = '%(asctime)-15s - %(levelname)-7s - %(name)s - %(message)s'
    logging.basicConfig(level=logging.INFO, format=log_format)

    # Load K8s configuration
    kubernetes.config.load_incluster_config()

    db_name = os.environ['DB_NAME']
    users_str = os.environ['USERS']
    users = json.loads(users_str)
    namespace = os.environ['NAMESPACE']
    bucket = os.environ['STORAGE_BUCKET']

    pg_host = os.environ['PGHOST']
    pg_port = os.environ['PGPORT']
    pg_database = os.environ['PGDATABASE']
    pg_user = os.environ['PGUSER']
    pg_password = os.environ['PGPASSWORD']

    stg_endpoint = os.environ['STORAGE_ENDPOINT']
    stg_tls_verify = (os.environ['STORAGE_TLS_VERIFY'].lower() == 'true')
    stg_acces_key = os.environ['STORAGE_ACCESS_KEY']
    stg_secret_key = os.environ['STORAGE_SECRET_KEY']

    postgres_db_backup(
        db_name, users, namespace, bucket,
        pg_host, pg_port, pg_database, pg_user, pg_password,
        stg_endpoint, stg_tls_verify, stg_acces_key, stg_secret_key)


if __name__ == '__main__':
    main()
