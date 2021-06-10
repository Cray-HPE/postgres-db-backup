
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

import unittest.mock as mock

import yaml

import postgres_db_backup


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


@mock.patch('postgres_db_backup.kubernetes.config')
@mock.patch('postgres_db_backup.postgres_db_backup', autospec=True)
def test_main(mock_pdb, mock_ks_config, monkeypatch):
    db_name = 'fake_db_name'
    monkeypatch.setenv('DB_NAME', db_name)
    namespace = 'fake_namespace'
    monkeypatch.setenv('NAMESPACE', namespace)
    bucket_name = 'fake_bucket'
    monkeypatch.setenv('STORAGE_BUCKET', bucket_name)
    postgres_db_backup.main()
    mock_ks_config.load_incluster_config.assert_called_once_with()
    mock_pdb.assert_called_once_with(db_name, namespace, bucket_name)
