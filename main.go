package main

import (
	"os"
	"time"

	"github.com/urfave/cli"
)

const (
	envPrefix = "DDNS_"
)

var version string

func run(c *cli.Context) {

}

func main() {
	app := cli.NewApp()
	app.Name = "ddns"
	app.Usage = "Command line tool for dynamically generating domain entries for EC2 instances"
	app.Version = version
	app.Action = run
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

	app.Run(os.Args)
}
