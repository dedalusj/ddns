package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/ec2/ec2iface"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/aws/aws-sdk-go/service/route53/route53iface"
	"github.com/pkg/errors"
	"github.com/urfave/cli"
)

const (
	envPrefix = "DDNS_"
)

var version string

type Config struct {
	Tag      string
	Domain   string
	Prefix   string
	Interval time.Duration
	Debug    bool
}

type Tag struct {
	Name  string
	Value string
}

func NewTag(tag string) (Tag, error) {
	pieces := strings.SplitN(tag, "=", 2)
	if len(pieces) < 2 {
		return Tag{}, fmt.Errorf("Invalid tag [%s]. Expected tag=value format", tag)
	}
	t := Tag{Name: pieces[0], Value: pieces[1]}
	log.WithFields(log.Fields{
		"name": t.Name,
		"value": t.Value,
	}).Info("Parsed tag")
	return t, nil
}

func (t Tag) String() string {
	return fmt.Sprintf("%s=%s", t.Name, t.Value)
}

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

func initLogging(debug bool) {
	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stderr)
	log.SetLevel(log.InfoLevel)
	if debug {
		log.SetLevel(log.DebugLevel)
	}
}

func getInstances(tag Tag, client ec2iface.EC2API) ([]*ec2.Instance, error) {
	params := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag:" + tag.Name),
				Values: aws.StringSlice([]string{tag.Value}),
			},
			{
				Name: aws.String("instance-state-name"),
				Values: aws.StringSlice([]string{"pending", "running"}),
			},
		},
	}

	resp, err := client.DescribeInstances(params)
	if err != nil {
		return []*ec2.Instance{}, errors.Wrapf(err, "Describing instances with tag [%s]", tag)
	}

	instances := []*ec2.Instance{}
	for _, r := range resp.Reservations {
		for _, i := range r.Instances {
			instances = append(instances, i)
		}
	}

	log.WithFields(log.Fields{
		"num": len(instances),
		"tag": tag,
	}).Debug("Fetched instaces")
	return instances, nil
}

func getIPs(tag Tag, client ec2iface.EC2API) ([]string, error) {
	instances, err := getInstances(tag, client)
	if err != nil {
		return []string{}, err
	}

	ips := []string{}
	for _, i := range instances {
		ips = append(ips, *i.PublicIpAddress)
	}
	return ips, nil
}

func gethostedZoneID(domain string, client route53iface.Route53API) (string, error) {
	hostedZoneRequest := &route53.ListHostedZonesByNameInput{
		DNSName:      aws.String(domain),
	}
	hostedZones, err := client.ListHostedZonesByName(hostedZoneRequest)
	if err != nil {
		return "", errors.Wrapf(err, "Listing hosted zones by name [%s]", domain)
	}
	if len(hostedZones.HostedZones) != 1 {
		return "", fmt.Errorf("Invalid number of hosted zones [%d] for domain [%s]", len(hostedZones.HostedZones), domain)
	}

	hostedZoneID := *hostedZones.HostedZones[0].Id
	log.WithField("id", hostedZoneID).Info("Fetched hosted zone id")
	return hostedZoneID, nil
}

func getRecords(hostedZoneID string, client route53iface.Route53API) ([]*route53.ResourceRecordSet, error) {
	recordSetsRequest := &route53.ListResourceRecordSetsInput{
		hostedZoneID: &hostedZoneID,
	}
	resp, err := client.ListResourceRecordSets(recordSetsRequest)
	if err != nil {
		return []*route53.ResourceRecordSet{}, errors.Wrapf(err, "Listing record sets for zone with ID [%s]", hostedZoneID)
	}
	return resp.ResourceRecordSets, nil
}

func getDNSNames(hostedZoneID, prefix string, client route53iface.Route53API) ([]string, error) {
	records, err := getRecords(hostedZoneID, client)
	if err != nil {
		return []string{}, err
	}

	names := []string{}
	for _, r := range records {
		if strings.HasPrefix(*r.Name, prefix) {
			names = append(names, *r.Name)
		}
	}
	log.WithFields(log.Fields{
		"num": len(names),
		"prefix": prefix,
		"hostedZone": hostedZoneID,
	}).Debug("Fetched DNS records")
	return names, nil
}

func StringSet(s []string) map[string]bool {
	set := map[string]bool{}
	for _, i := range s {
		set[i] = true
	}
	return set
}

func getIPFromDNS(dnsName, prefix string) string {
	pieces := strings.SplitN(dnsName, ".", 2)
	return strings.Replace(pieces[0][len(prefix):], "-", ".", -1)
}

func getDNSFromIP(ip, prefix string) string {
	return prefix + strings.Replace(ip, ".", "-", -1)
}

func findCreatedInstances(instanceIPSet, dnsIPSet map[string]bool) []string {
	createdInstances := []string{}
	for ip := range instanceIPSet {
		if _, ok := dnsIPSet[ip]; !ok {
			newIP := string(ip)
			log.WithField("ip", newIP).Debug("Found new instance")
			createdInstances = append(createdInstances, newIP)
		}
	}
	return createdInstances
}

func findDeletedInstances(instanceIPSet, dnsIPSet map[string]bool) []string {
	deletedInstances := []string{}
	for ip := range dnsIPSet {
		if _, ok := instanceIPSet[ip]; !ok {
			newIP := string(ip)
			log.WithField("ip", newIP).Debug("Found removed instance")
			deletedInstances = append(deletedInstances, newIP)
		}
	}
	return deletedInstances
}

func registerCreatedInstances(createdInstanceIPs []string, prefix, domain, hostedZoneID string, client route53iface.Route53API) error {
	if len(createdInstanceIPs) == 0 {
		return nil
	}

	params := &route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{},
		},
		hostedZoneID: aws.String(hostedZoneID),
	}

	for _, ip := range createdInstanceIPs {
		change := &route53.Change{
			Action: aws.String("CREATE"),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String(getDNSFromIP(ip, prefix) + "." + domain),
				Type: aws.String("A"),
				ResourceRecords: []*route53.ResourceRecord{{Value: aws.String(ip)}},
				TTL: aws.Int64(60),
			},
		}
		params.ChangeBatch.Changes = append(params.ChangeBatch.Changes, change)
	}

	_, err := client.ChangeResourceRecordSets(params)
	if err != nil {
		return errors.Wrap(err, "Registering instance IPs")
	}

	log.WithFields(log.Fields{
		"number": len(createdInstanceIPs),
	}).Info("Registered DNS name for created instance")
	return nil
}

func removeDeletedInstances(deletedInstanceIPs []string, prefix, domain, hostedZoneID string, client route53iface.Route53API) error {
	if len(deletedInstanceIPs) == 0 {
		return nil
	}

	params := &route53.ChangeResourceRecordSetsInput{
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{},
		},
		hostedZoneID: aws.String(hostedZoneID),
	}

	for _, ip := range deletedInstanceIPs {
		change := &route53.Change{
			Action: aws.String("DELETE"),
			ResourceRecordSet: &route53.ResourceRecordSet{
				Name: aws.String(getDNSFromIP(ip, prefix) + "." + domain),
				Type: aws.String("A"),
				ResourceRecords: []*route53.ResourceRecord{{Value: aws.String(ip)}},
				TTL: aws.Int64(60),
			},
		}
		params.ChangeBatch.Changes = append(params.ChangeBatch.Changes, change)
	}

	_, err := client.ChangeResourceRecordSets(params)
	if err != nil {
		return errors.Wrap(err, "Removing instance IPs")
	}

	log.WithFields(log.Fields{
		"number": len(deletedInstanceIPs),
	}).Info("Removed DNS name for deleted instance")
	return nil
}

func reconcile(instanceIPs, dnsNames []string, prefix, domain, hostedZoneID string, client route53iface.Route53API) error {
	dnsIPs := []string{}
	for _, dnsName := range dnsNames {
		dnsIPs = append(dnsIPs, getIPFromDNS(dnsName, prefix))
	}

	dnsIPSet := StringSet(dnsIPs)
	instanceIPSet := StringSet(instanceIPs)

	createdInstanceIPs := findCreatedInstances(instanceIPSet, dnsIPSet)
	registerErr := registerCreatedInstances(createdInstanceIPs, prefix, domain, hostedZoneID, client)
	if registerErr != nil {
		return registerErr
	}

	deletedInstanceIPs := findDeletedInstances(instanceIPSet, dnsIPSet)
	removeErr := removeDeletedInstances(deletedInstanceIPs, prefix, domain, hostedZoneID, client)
	if removeErr != nil {
		return removeErr
	}

	return nil
}

func run(c *Config, clients *Clients) {
	initLogging(c.Debug)
	log.WithField("version", version).Info("DDNS")

	tag, err := NewTag(c.Tag)
	if err != nil {
		log.Fatal(err)
	}

	if c.Domain[len(c.Domain)-1] != '.' {
		c.Domain += "."
	}
	hostedZoneID, err := gethostedZoneID(c.Domain, clients.Route53Client)
	if err != nil {
		log.Fatal(err)
	}

	for {
		time.Sleep(c.Interval)
		ips, err := getIPs(tag, clients.EC2Client)
		if err != nil {
			log.Warnf("Error while fetching IPs: %s", err)
			continue
		}

		dnsEntries, err := getDNSNames(hostedZoneID, c.Prefix, clients.Route53Client)
		if err != nil {
			log.Warnf("Error while fetching DNS entries: %s", err)
			continue
		}

		err = reconcile(ips, dnsEntries, c.Prefix, c.Domain, hostedZoneID, clients.Route53Client)
		if err != nil {
			log.Warnf("Error while reconciling DNS entries: %s", err)
			continue
		}
	}
}

func main() {
	app := cli.NewApp()
	app.Name = "ddns"
	app.Usage = "Command line tool for dynamically generating domain entries for EC2 instances"
	app.Version = version

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:   "tag, t",
			Usage:  "Tag used to filter EC2 instances. Format tag=value",
			EnvVar: envPrefix + "TAG",
		},
		cli.StringFlag{
			Name:   "domain, d",
			Usage:  "Domain id where records will be added",
			EnvVar: envPrefix + "DOMAIN",
		},
		cli.StringFlag{
			Name:   "prefix, p",
			Usage:  "Prefix to be added to the IP when creating records",
			Value:  "ddns-",
			EnvVar: envPrefix + "PREFIX",
		},
		cli.DurationFlag{
			Name:   "interval, i",
			Usage:  "Interval for querying the EC2 isntances",
			Value:  30 * time.Second,
			EnvVar: envPrefix + "INTERVAL",
		},
		cli.BoolFlag{
			Name:   "debug, D",
			Usage:  "Enable debug logging",
			EnvVar: envPrefix + "DEBUG",
		},
	}

	app.Action = func(c *cli.Context) error {
		run(&Config{
			Tag: c.String("tag"),
			Domain: c.String("domain"),
			Prefix: c.String("prefix"),
			Interval: c.Duration("interval"),
			Debug: c.Bool("debug"),
		}, &Clients{
			EC2Client: NewEC2Client(),
			Route53Client: NewRoute53Client(),
		})
		return nil
	}

	app.Run(os.Args)
}
