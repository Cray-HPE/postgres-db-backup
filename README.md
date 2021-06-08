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

```
docker run --rm postgres-db-backup:0.1.0 pip freeze
```
