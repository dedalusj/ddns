package main

import (
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/route53/route53iface"
)

type Clients struct {
	EC2Client     ec2iface.EC2API
	Route53Client route53iface.Route53API
}

func NewEC2Client() ec2iface.EC2API {
	s := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Region: aws.String(os.Getenv("AWS_DEFAULT_REGION"))},
	}))
	return ec2.New(s)
}

func NewRoute53Client() route53iface.Route53API {
	s := session.Must(session.NewSessionWithOptions(session.Options{
		Config: aws.Config{Region: aws.String(os.Getenv("AWS_DEFAULT_REGION"))},
	}))
	return route53.New(s)
}


