DDNS
====

[![Build Status](https://travis-ci.org/dedalusj/ddns.svg?branch=master)](https://travis-ci.org/dedalusj/ddns)

DDNS is a command line tool that maintains entries in a Route53 hosted zone in sync with the EC2 instances in a scaling group.

It does that by querying all pending and running EC2 instances with a specified tag and creating entries in a specified hosted zone. It will also remove all entries without a corresponding running EC2 instance.

#### Command Line Arguments

- `--tag`: Specify the tag and value to use when querying for EC2 instances. Format `tag=value`.
- `--domain`: Specify the Route53 domain where the entries will be created. DDNS will find the hosted zone associated with the domain.
- `--prefix`: Prefix to add to the Route53 entries. If the IP address of an instance is `127.0.0.1` the entry will be `<prefix>127-0-0-1.<domain>`. Default `ddns-`.
- `--interval`: Interval at which the DDNS will sync the Route53 entries with the EC2 instances. See [https://golang.org/pkg/time/#ParseDuration](https://golang.org/pkg/time/#ParseDuration) for format. Default `30s`.
- `--debug`: Enable debug logging.

The command line parameters can also be controlled with an environment variable of the form `DDNS_<parameter_name>`.

#### Development

DDNS relies on [Glide](https://glide.sh) to version its dependencies. After installing Glide simply run `glide up` to download the dependencies.

To build DDNS run `make build`.
