
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

import decimal
import json
import subprocess
import unittest.mock as mock

import pytest
import yaml

import postgres_db_backup


@mock.patch('postgres_db_backup.psycopg2')
def test_query_replicas_no_replicas(m_pg):
    pg_host = 'fake_pg_host'
    pg_port = 'fake_pg_port'
    pg_database = 'fake_pg_database'
    pg_user = 'fake_pg_user'
    pg_password = 'fake_pg_password'

    with m_pg.connect.return_value as m_conn:
        with m_conn.cursor.return_value as m_curs:
            m_curs.fetchall.return_value = []  # No replicas

    res = postgres_db_backup.query_replicas(
        pg_host, pg_port, pg_database, pg_user, pg_password)

    m_pg.connect.assert_called_once_with(
        dbname=pg_database, user=pg_user, password=pg_password,
        host=pg_host, port=pg_port)

    assert res is None


@mock.patch('postgres_db_backup.psycopg2')
def test_query_replicas_one_replica_caught_up(m_pg):
    pg_host = 'fake_pg_host'
    pg_port = 'fake_pg_port'
    pg_database = 'fake_pg_database'
    pg_user = 'fake_pg_user'
    pg_password = 'fake_pg_password'

    with m_pg.connect.return_value as m_conn:
        with m_conn.cursor.return_value as m_curs:
            m_curs.fetchall.return_value = [
                ('fake_name_1', decimal.Decimal(0)),
            ]

    res = postgres_db_backup.query_replicas(
        pg_host, pg_port, pg_database, pg_user, pg_password)

    assert res == 'fake_name_1'


@mock.patch('postgres_db_backup.psycopg2')
def test_query_replicas_one_replica_behind(m_pg):
    pg_host = 'fake_pg_host'
    pg_port = 'fake_pg_port'
    pg_database = 'fake_pg_database'
    pg_user = 'fake_pg_user'
    pg_password = 'fake_pg_password'

    with m_pg.connect.return_value as m_conn:
        with m_conn.cursor.return_value as m_curs:
            m_curs.fetchall.return_value = [
                ('fake_name_1', decimal.Decimal(1048577)),  # Too far behind.
            ]

    res = postgres_db_backup.query_replicas(
        pg_host, pg_port, pg_database, pg_user, pg_password)

    assert res is None


@mock.patch('postgres_db_backup.psycopg2')
def test_query_replicas_picks_closest(m_pg):
    pg_host = 'fake_pg_host'
    pg_port = 'fake_pg_port'
    pg_database = 'fake_pg_database'
    pg_user = 'fake_pg_user'
    pg_password = 'fake_pg_password'

    with m_pg.connect.return_value as m_conn:
        with m_conn.cursor.return_value as m_curs:
            m_curs.fetchall.return_value = [
                ('fake_name_1', decimal.Decimal(20)),
                ('fake_name_2', decimal.Decimal(10)),
            ]

    res = postgres_db_backup.query_replicas(
        pg_host, pg_port, pg_database, pg_user, pg_password)

    assert res == 'fake_name_2'


@mock.patch('postgres_db_backup.query_replicas', autospec=True)
def test_select_target_pg_host_use_replica(m_qr):
    # When there's a replica that can be used then that's used.
    pg_host = 'fake_pg_host'
    pg_port = 'fake_pg_port'
    pg_database = 'fake_pg_database'
    pg_user = 'fake_pg_user'
    pg_password = 'fake_pg_password'

    res = postgres_db_backup.select_target_pg_host(
        pg_host, pg_port, pg_database, pg_user, pg_password)

    m_qr.assert_called_once_with(pg_host, pg_port, pg_database, pg_user, pg_password)

    assert res is m_qr.return_value


@mock.patch('postgres_db_backup.query_replicas', autospec=True)
def test_select_target_pg_host_use_leader(m_qr):
    # When there's no replica that can be used then leader is used.
    pg_host = 'fake_pg_host'
    pg_port = 'fake_pg_port'
    pg_database = 'fake_pg_database'
    pg_user = 'fake_pg_user'
    pg_password = 'fake_pg_password'

    m_qr.return_value = None

    res = postgres_db_backup.select_target_pg_host(
        pg_host, pg_port, pg_database, pg_user, pg_password)

    assert res == pg_host


@mock.patch('postgres_db_backup.subprocess.Popen')
def test_pg_dump_to_storage_works(m_popen):
    m_popen.return_value.returncode = 0

    target_host = 'fake_target_host'
    key_base = 'fake_key_base'
    m_stg_client = mock.Mock()
    bucket = 'fake_bucket'
    postgres_db_backup.pg_dump_to_storage(
        target_host, key_base, m_stg_client, bucket)

    exp_command = ['pg_dumpall', '-c', '-h', target_host]
    m_popen.assert_called_once_with(exp_command, stdout=subprocess.PIPE)

    exp_pgdump_key = f'{key_base}.psql'
    m_stg_client.upload_fileobj.assert_called_once_with(
        m_popen.return_value.stdout,
        bucket,
        exp_pgdump_key,
        Callback=postgres_db_backup.upload_fileobj_cb)

    m_popen.return_value.wait.assert_called_once_with()


@mock.patch('postgres_db_backup.subprocess.Popen')
def test_pg_dump_to_storage_bad_exit_code(m_popen):
    # When the exit status of the pg_dumpall subprocess is not 0 an exception is
    # raised.
    m_popen.return_value.returncode = 1
    target_host = 'fake_target_host'
    key_base = 'fake_key_base'
    m_stg_client = mock.Mock()
    bucket = 'fake_bucket'
    with pytest.raises(Exception, match="pg_dumpall command failed."):
        postgres_db_backup.pg_dump_to_storage(
            target_host, key_base, m_stg_client, bucket)


def test_fetch_secrets_yaml():
    mock_secret = mock.Mock()
    mock_secret.api_version = 'fake_api_version'
    mock_secret.kind = 'fake_kind'
    mock_secret.type = 'fake_type'
    mock_secret.metadata = mock.Mock()
    mock_secret.metadata.name = 'fake_name'
    mock_secret.metadata.namespace = 'fake_namespace'
    mock_secret.metadata.labels = {'fake_label_name': 'fake_label_value'}
    mock_secret.data = {'fake_data_name': 'fake_data_value'}

    ks_core_v1 = mock.Mock()
    ks_core_v1.read_namespaced_secret.return_value = mock_secret

    name = 'fake_name_param'
    namespace = 'fake_namespace_param'
    res = postgres_db_backup.fetch_secrets_yaml(ks_core_v1, name, namespace)

    ks_core_v1.read_namespaced_secret.assert_called_once_with(name, namespace)

    exp_res = yaml.dump({
        'apiVersion': 'fake_api_version',
        'kind': 'fake_kind',
        'type': 'fake_type',
        'metadata': {
            'name': 'fake_name',
            'namespace': 'fake_namespace',
            'labels': {'fake_label_name': 'fake_label_value'},
        },
        'data': {'fake_data_name': 'fake_data_value'},
    })

    assert exp_res == res


def test_user_name_to_secret_name():
    assert postgres_db_backup.user_name_to_secret_name('user1') == 'user1'
    # _ gets converted to -
    assert postgres_db_backup.user_name_to_secret_name('service_account') == 'service-account'


@mock.patch('postgres_db_backup.io')
@mock.patch('postgres_db_backup.kubernetes.client', autospec=True)
@mock.patch('postgres_db_backup.fetch_secrets_yaml', autospec=True)
def test_k8s_objects_to_storage_no_user(m_fsy, m_kc, m_io):
    users = []
    db_name = 'fake_db_name'
    namespace = 'fake_db_name'
    stg_client = mock.Mock()
    bucket = 'fake_bucket'
    key_base = 'fake_key_base'

    m_fsy.side_effect = (
        'pg_yaml',
        'sb_yaml',
        Exception()
    )
    postgres_db_backup.k8s_objects_to_storage(
        db_name, users, namespace, stg_client, bucket, key_base)

    m_kc.CoreV1Api.assert_called_once_with()
    m_fsy.assert_any_call(
        m_kc.CoreV1Api.return_value, f'postgres.{db_name}.credentials', namespace)
    m_fsy.assert_any_call(
        m_kc.CoreV1Api.return_value, f'standby.{db_name}.credentials', namespace)
    assert m_fsy.call_count == 2

    exp_creds_contents = b'''
---
pg_yaml

---
sb_yaml
'''

    m_io.BytesIO.assert_called_with(exp_creds_contents)
    stg_client.upload_fileobj(mock.ANY, bucket, f'{key_base}.manifest')


@mock.patch('postgres_db_backup.io')
@mock.patch('postgres_db_backup.kubernetes.client', autospec=True)
@mock.patch('postgres_db_backup.fetch_secrets_yaml', autospec=True)
def test_k8s_objects_to_storage_user(m_fsy, m_kc, m_io):
    users = ['service_account']
    db_name = 'fake_db_name'
    namespace = 'fake_db_name'
    stg_client = mock.Mock()
    bucket = 'fake_bucket'
    key_base = 'fake_key_base'

    m_fsy.side_effect = (
        'sa_yaml',
        'pg_yaml',
        'sb_yaml',
        Exception()
    )
    postgres_db_backup.k8s_objects_to_storage(
        db_name, users, namespace, stg_client, bucket, key_base)

    m_kc.CoreV1Api.assert_called_once_with()
    # Note that _ got converted to - for service-account.
    m_fsy.assert_any_call(
        m_kc.CoreV1Api.return_value, f'service-account.{db_name}.credentials', namespace)
    m_fsy.assert_any_call(
        m_kc.CoreV1Api.return_value, f'postgres.{db_name}.credentials', namespace)
    m_fsy.assert_any_call(
        m_kc.CoreV1Api.return_value, f'standby.{db_name}.credentials', namespace)
    assert m_fsy.call_count == 3

    exp_creds_contents = b'''
---
sa_yaml

---
pg_yaml

---
sb_yaml
'''

    m_io.BytesIO.assert_called_with(exp_creds_contents)
    stg_client.upload_fileobj(mock.ANY, bucket, f'{key_base}.manifest')


@mock.patch('postgres_db_backup.datetime')
def test_calc_key_base(m_datetime):
    timestamp = 'fake_timestamp'
    m_datetime.datetime.utcnow.return_value.isoformat.return_value = timestamp
    db_name = 'fake_db_name'
    res = postgres_db_backup.calc_key_base(db_name)
    exp = f'{db_name}-{timestamp}'
    assert res == exp


def test_get_keys_for_db():
    # get_keys_for_db calls list_objects with the bucket and prefix.
    # This returns a dict with `Contents` set to a list of dicts (one for each
    # object in the bucket that matches the prefix) that has a
    # `Key`. get_keys_for_db returns all the Key values as a list.
    stg_client = mock.Mock()
    stg_client.list_objects.return_value = {
        'Contents': [
            {'Key': 'key1'},
            {'Key': 'key2'},
        ],
    }
    db_name = 'fake_db_name'
    bucket = 'fake_bucket'
    res = postgres_db_backup.get_keys_for_db(stg_client, bucket, db_name)
    exp_res = ['key1', 'key2', ]
    assert res == exp_res

    stg_client.list_objects.assert_called_once_with(
        Bucket=bucket, Prefix=f'{db_name}-')


def test_calc_timestamp():
    # calc_timestamp() extracts the timestamp from a key. The key is like
    # <db_name>-<timestamp>.<suffix>.
    db_name = 'fake_db_name'
    fake_timestamp = '2021-06-10T15:07:42'
    key = f'{db_name}-{fake_timestamp}.manifest'
    res = postgres_db_backup.calc_timestamp(db_name, key)
    assert res == fake_timestamp


def test_calc_timestamps():
    # calc_timestamps takes a list of keys and returns a sorted list of
    # unique timestamps from the keys.
    db_name = 'fake_db_name'
    fake_timestamp_1 = '2021-06-09T15:07:42'
    fake_timestamp_2 = '2021-06-10T18:11:10'
    # Keys are out of timestamp order here, calc_timestamps sorts the results.
    keys = [
        f'{db_name}-{fake_timestamp_2}.manifest',
        f'{db_name}-{fake_timestamp_2}.psql',
        f'{db_name}-{fake_timestamp_1}.manifest',
        f'{db_name}-{fake_timestamp_1}.psql',
    ]
    res = postgres_db_backup.calc_timestamps(db_name, keys)
    exp_res = [fake_timestamp_1, fake_timestamp_2]  # sorted!
    assert res == exp_res


@mock.patch('postgres_db_backup.get_keys_for_db', autospec=True)
@mock.patch('postgres_db_backup.calc_timestamps', autospec=True)
def test_get_backup_timestamps(m_cts, m_gkd):
    stg_client = mock.Mock()
    bucket = 'fake_bucket'
    db_name = 'fake_db_name'
    (res_keys, res_timestamps) = postgres_db_backup.get_backup_timestamps(
        stg_client, bucket, db_name)
    m_gkd.assert_called_once_with(stg_client, bucket, db_name)
    m_cts.assert_called_once_with(db_name, m_gkd.return_value)
    assert res_keys is m_gkd.return_value
    assert res_timestamps is m_cts.return_value


def test_calc_timestamps_to_delete_empty():
    # When there are no timestamps, there's none to delete.
    backup_timestamps = []
    res = postgres_db_backup.calc_timestamps_to_delete(backup_timestamps)
    assert res == []


def test_calc_timestamps_to_delete_one():
    # When there's 1 timestamp, there's none to delete.
    backup_timestamps = ['ts1']
    res = postgres_db_backup.calc_timestamps_to_delete(backup_timestamps)
    assert res == []


def test_calc_timestamps_to_delete_two():
    # When there's 2 timestamps, there's 1 to delete.
    backup_timestamps = ['ts1', 'ts2']
    res = postgres_db_backup.calc_timestamps_to_delete(backup_timestamps)
    assert res == ['ts1']


def test_calc_timestamps_to_delete():
    # When there's 3 timestamps, there's 2 to delete.
    backup_timestamps = ['ts1', 'ts2', 'ts3']
    res = postgres_db_backup.calc_timestamps_to_delete(backup_timestamps)
    assert res == ['ts1', 'ts2']


def test_delete_backups():
    stg_client = mock.Mock()
    bucket = 'fake_bucket'
    db_name = 'fake_db_name'
    fake_timestamp_1 = '2021-06-09T15:07:42'
    fake_timestamp_2 = '2021-06-10T18:11:10'
    # Keys are out of timestamp order here, calc_timestamps sorts the results.
    keys = [
        f'{db_name}-{fake_timestamp_2}.manifest',
        f'{db_name}-{fake_timestamp_2}.psql',
        f'{db_name}-{fake_timestamp_1}.manifest',
        f'{db_name}-{fake_timestamp_1}.psql',
    ]
    timestamps_to_delete = [fake_timestamp_1]
    postgres_db_backup.delete_backups(
        stg_client, bucket, db_name, keys, timestamps_to_delete
    )

    # The keys with fake_timestamp_1 were deleted.
    stg_client.delete_object.assert_any_call(
        Bucket=bucket, Key=f'{db_name}-{fake_timestamp_1}.manifest')
    stg_client.delete_object.assert_any_call(
        Bucket=bucket, Key=f'{db_name}-{fake_timestamp_1}.psql')
    assert stg_client.delete_object.call_count == 2


@mock.patch('postgres_db_backup.get_backup_timestamps', autospec=True)
@mock.patch('postgres_db_backup.calc_timestamps_to_delete', autospec=True)
@mock.patch('postgres_db_backup.delete_backups', autospec=True)
def test_cleanup_old_backups(m_db, m_cttd, m_gbt):
    m_gbt.return_value = (mock.sentinel.keys, mock.sentinel.backup_timestamps)
    stg_client = mock.Mock()
    bucket = 'fake_bucket'
    db_name = 'fake_db_name'
    postgres_db_backup.cleanup_old_backups(stg_client, bucket, db_name)
    m_gbt.assert_called_once_with(stg_client, bucket, db_name)
    m_cttd.assert_called_once_with(mock.sentinel.backup_timestamps)
    m_db.assert_called_once_with(
        stg_client, bucket, db_name, mock.sentinel.keys, m_cttd.return_value)


@mock.patch('postgres_db_backup.select_target_pg_host', autospec=True)
@mock.patch('postgres_db_backup.boto3', autospec=True)
@mock.patch('postgres_db_backup.calc_key_base', autospec=True)
@mock.patch('postgres_db_backup.pg_dump_to_storage', autospec=True)
@mock.patch('postgres_db_backup.k8s_objects_to_storage', autospec=True)
@mock.patch('postgres_db_backup.cleanup_old_backups', autospec=True)
def test_postgres_db_backup(m_cob, m_kots, m_pdts, m_ckb, m_boto3, m_stpg):
    db_name = 'fake_db_name'
    users = ['fake_user']
    namespace = 'fake_namespace'
    bucket = 'fake_bucket'
    pg_host = 'fake_pg_host'
    pg_port = 'fake_pg_port'
    pg_database = 'fake_pg_database'
    pg_user = 'fake_pg_user'
    pg_password = 'fake_pg_password'
    stg_endpoint = 'fake_stg_endpoint'
    stg_tls_verify = False
    stg_access_key = 'fake_stg_access_key'
    stg_secret_key = 'fake_stg_secret_key'
    postgres_db_backup.postgres_db_backup(
        db_name, users, namespace, bucket,
        pg_host, pg_port, pg_database, pg_user, pg_password,
        stg_endpoint, stg_tls_verify, stg_access_key, stg_secret_key)

    m_stpg.assert_called_once_with(
        pg_host, pg_port, pg_database, pg_user, pg_password)

    m_boto3.client.assert_called_once_with(
        's3',
        endpoint_url=stg_endpoint,
        verify=stg_tls_verify,
        aws_access_key_id=stg_access_key,
        aws_secret_access_key=stg_secret_key)

    m_ckb.assert_called_once_with(db_name)
    m_pdts.assert_called_once_with(
        m_stpg.return_value, m_ckb.return_value, m_boto3.client.return_value, bucket)
    m_kots.assert_called_once_with(
        db_name, users, namespace, m_boto3.client.return_value, bucket, m_ckb.return_value)
    m_cob.assert_called_once_with(m_boto3.client.return_value, bucket, db_name)


@mock.patch('postgres_db_backup.kubernetes.config')
@mock.patch('postgres_db_backup.postgres_db_backup', autospec=True)
def test_main(mock_pdb, mock_ks_config, monkeypatch):
    db_name = 'fake_db_name'
    monkeypatch.setenv('DB_NAME', db_name)
    users = ['fake_user']
    monkeypatch.setenv('USERS', json.dumps(users))
    namespace = 'fake_namespace'
    monkeypatch.setenv('NAMESPACE', namespace)
    pg_host = 'fake_pg_host'
    monkeypatch.setenv('PGHOST', pg_host)
    pg_port = 'fake_pg_port'
    monkeypatch.setenv('PGPORT', pg_port)
    pg_database = 'fake_pg_database'
    monkeypatch.setenv('PGDATABASE', pg_database)
    pg_user = 'fake_pg_user'
    monkeypatch.setenv('PGUSER', pg_user)
    pg_password = 'fake_pg_password'
    monkeypatch.setenv('PGPASSWORD', pg_password)
    bucket_name = 'fake_bucket'
    monkeypatch.setenv('STORAGE_BUCKET', bucket_name)
    stg_endpoint = 'fake_storage_endpoint'
    monkeypatch.setenv('STORAGE_ENDPOINT', stg_endpoint)
    stg_tls_verify = False
    monkeypatch.setenv('STORAGE_TLS_VERIFY', str(stg_tls_verify))
    stg_acces_key = 'fake_stg_access_key'
    monkeypatch.setenv('STORAGE_ACCESS_KEY', stg_acces_key)
    stg_secret_key = 'fake_stg_secret_key'
    monkeypatch.setenv('STORAGE_SECRET_KEY', stg_secret_key)

    postgres_db_backup.main()
    mock_ks_config.load_incluster_config.assert_called_once_with()
    mock_pdb.assert_called_once_with(
        db_name, users, namespace, bucket_name,
        pg_host, pg_port, pg_database, pg_user, pg_password,
        stg_endpoint, stg_tls_verify, stg_acces_key, stg_secret_key)
