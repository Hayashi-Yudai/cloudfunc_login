# cloudfunc_login

## Description

It is an example of authentication function for Cloud Function. It receive requests from other applications and returns hashed password of requested users.
This program assumes that authentication infos are stored in google BigQuery.

## Requirements

- Go 1.13

## In Cloud Functions

For use of this example, copy all except for `EnvLoad` and `main` functions.
