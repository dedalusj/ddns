package main

import (
	"fmt"
	"strings"

	log "github.com/Sirupsen/logrus"
)

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
