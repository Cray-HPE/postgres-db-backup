This is a tool that will take a backup of a postgres DB running in Kubernetes.
The backup is stored in s3 (radosgw).

## Building

```
docker build . --tag postgres-db-backup:0.1.0
```

## Running

```
docker run --rm postgres-db-backup:0.1.0
```

## Generating constraints.txt

Clear out the current contents of constraints.txt.

Run the following command:

```
docker run --rm postgres-db-backup:0.1.0 pip freeze
```

Put the result in constraints.txt.

Run the codestyle test below.
Part of the output is the output of pip freeze after installing the test requirements.
Update the constraints.txt with that output.

## Running tests

```
docker build --tag postgres-db-backup-codestyle --target codestyle . &&
docker run --rm postgres-db-backup-codestyle
```

## Testing using the Helm chart

The helm chart in kubernetes/postgres-db-backup is useful for testing.

To test on vshasta:

Upload the built image:
`craypc ahoy alpha container-images push postgres-db-backup:0.1.0`

Copy the chart to the node (replace zone and node name with your vshasta):
`gcloud compute scp --recurse --zone us-central1-f kubernetes/postgres-db-backup ncn-m001-8a520ee2:`

Create a values.yaml file on the node (replace `vshasta-bknudson-3568233492353` with the output from the image upload):
```
cat > myvalues.yaml <<EOF
image:
  repository: "gcr.io/vshasta-bknudson-3568233492353/postgres-db-backup"
  tag: "0.1.0"
EOF
```

Deploy the chart and check the log:
```
helm install -n services postgres-db-backup postgres-db-backup --values myvalues.yaml

kubectl get pods -n services | grep postgres-db-backup
```

Clean up:

```
helm uninstall -n services postgres-db-backup

rm -r postgres-db-backup
```

### Getting the backup off the test ncn

```
kubectl get secret -n services wlm-s3-credentials -ojsonpath='{.data.access_key}' | base64 -d ; echo

kubectl get secret -n services wlm-s3-credentials -ojsonpath='{.data.secret_key}' | base64 -d ; echo

kubectl get secret -n services wlm-s3-credentials -ojsonpath='{.data.s3_endpoint}' | base64 -d ; echo

# replace the values in the script below with the output from above.

mkdir keycloak_backup
cd keycloak_backup

python3
>>>
import boto3

s3_client = boto3.client(
    's3',
    endpoint_url='http://ncn-s001-2c739d88:8080',
    aws_access_key_id='C7JJTKZBHXNWO1T2FQ2N',
    aws_secret_access_key='usxKUeUr8PhzQbywjDp8Ckei8RRerGYcfL54i9BY',
    verify=False)

s3_client.download_file('wlm', 'keycloak-pgdump.mysql', 'pg_dump.mysql')
s3_client.download_file('wlm', 'keycloak-creds.yaml', 'creds.yaml')
<<<
```
