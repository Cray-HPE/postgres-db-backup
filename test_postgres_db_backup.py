
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


@mock.patch('postgres_db_backup.kubernetes.config')
@mock.patch('postgres_db_backup.postgres_db_backup')
def test_main(mock_pdb, mock_ks_config, monkeypatch):
    bucket_name = 'fake_bucket'
    monkeypatch.setenv('STORAGE_BUCKET', 'fake_bucket')
    postgres_db_backup.main()
    mock_ks_config.load_incluster_config.assert_called_once_with()
    mock_pdb.assert_called_once_with(bucket_name)
