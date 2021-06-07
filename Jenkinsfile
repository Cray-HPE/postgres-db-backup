@Library('dst-shared@master') _

dockerBuildPipeline {
 app = "postgres-db-backup"
 name = "cms-postgres-db-backup"
 description = "Cray management system Postgres DB Backup utility"
 repository = "cray"
 imagePrefix = "cray"
 product = "csm"
 githubPushRepo = "Cray-HPE/postgres-db-backup"
 githubPushBranches = /(release\/.*|master)/
}
