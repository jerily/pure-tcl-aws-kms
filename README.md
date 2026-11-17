# pure-tcl-aws-kms

AWS KMS client implemented in Tcl 9.1. Its only package dependency is
[`pure-tcl-aws-core`](https://github.com/jerily/pure-tcl-aws-core), which supplies
HTTP, JSON, XML, credentials and signing. No AWS C++ SDK is required.

```tcl
package require pure-tcl-aws-kms 0.1.0
set client [::aws::kms::create {region us-east-1}]
try {
    puts [$client list_keys]
} finally {
    $client destroy
}
```

`package require awskms 1.0.19` is also supported. Use one implementation
of the `awskms` package per interpreter. Existing namespace commands
(`::aws::kms::method $client ...`) and client methods share the same behavior.
Client destruction returns an empty result. Unknown methods and invalid arguments
raise Tcl errors. See the core README for credentials, configuration and retries.

## Methods

| Method | Arguments after the client handle |
| --- | --- |
| `list_keys` | — |
| `create_key` | — |
| `describe_key` | `arn` |
| `enable_key` | `arn` |
| `disable_key` | `arn` |
| `schedule_key_deletion` | `arn ?days?` |
| `cancel_key_deletion` | `arn` |
| `encrypt` | `arn bytes` |
| `decrypt` | `bytes` |
| `generate_data_key` | `arn size` |
| `generate_random` | `size` |

## Behavior

Cryptographic operations run in AWS KMS. Binary inputs and outputs are Tcl byte arrays; the JSON transport handles base64 internally. `generate_data_key` returns `{plaintext ciphertext}`. Key listing follows every page.

## Install and examples

Install the core and its dependencies first, then run:

```sh
make install PREFIX=/your/prefix
```

The release recipe declares examples with `file` entries. After registry installation:

```sh
ttrek run -package pure-tcl-aws-kms -script example-list-keys
ttrek run -package pure-tcl-aws-kms -script example-describe-key -- key-id
```

`./run-example.sh --help` lists arguments. Set AWS credentials and `AWS_REGION`
or `AWS_DEFAULT_REGION` before running AWS examples. Examples read resources or sign URLs.

## Tests

With Tcl 9.1 and the dependencies on `TCLLIBPATH`:

```sh
make test TCLSH=tclsh9.1
```

Python 3 supplies local HTTP fixtures. Tests use fake credentials and do not
contact AWS. They check requests, result formats, and error handling.

## Install with ttrek

If you do not have the ttrek client, get it from [ttrek.sh](https://ttrek.sh).
Then install the package:

```sh
ttrek install pure-tcl-aws-kms
```
