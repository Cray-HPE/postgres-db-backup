
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

import io
import logging
import os

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
    resp = kubernetes.stream.stream(
        ks_core_v1.connect_get_namespaced_pod_exec,
        pod_name,
        namespace,
        container=container_name,
        command=exec_command,
        stderr=True, stdin=False,
        stdout=True, tty=False,
        _preload_content=False)

    # FIXME: is there some way to stream the output directly to s3?
    pgdump_filename = '/work/pg_dump.psql'

    with open(pgdump_filename, 'w') as f:
        while resp.is_open():
            resp.update(timeout=1)
            any_output = False
            if resp.peek_stdout():
                s = resp.read_stdout()
                logging.info("Read %s from stdout", len(s))
                f.write(s)
                any_output = True
            if resp.peek_stderr():
                s = resp.read_stderr()
                logging.warn("Output on stderr:", s)
                any_output = True
            if not any_output:
                logging.info("Nothing in stout/stderr.")
        resp.close()
        logging.info("Closed pg_dumpall stream")

    # FIXME: this isn't going to work if the file is large,
    # figure out a better way to log some info about the file.
    with open(pgdump_filename, 'r') as f:
        logging.info("Contents of %s", pgdump_filename)
        logging.info("-------------------------")
        logging.info('\n%s', f.read())
        logging.info("-------------------------")

    stg_endpoint = os.environ['STORAGE_ENDPOINT']
    stg_tls_verify = (os.environ['STORAGE_TLS_VERIFY'].lower() == 'true')
    stg_acces_key = os.environ['STORAGE_ACCESS_KEY']
    stg_secret_key = os.environ['STORAGE_SECRET_KEY']

    pgdump_key = f'{db_name}.psql'
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
    stg_client.upload_file(pgdump_filename, bucket, pgdump_key)
    logging.info("Completed sending pg_dump file to storage.")

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

    creds_key = f'{db_name}.manifest'
    stg_client.upload_fileobj(
        io.BytesIO(creds_contents.encode('utf-8')), bucket, creds_key)
    logging.info("Completed sending creds file to storage. key=%r", creds_key)


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
