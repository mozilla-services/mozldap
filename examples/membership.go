// List all the groups a given user is a member of

package main

import (
	"crypto/tls"
	"fmt"
	"os"
	"strings"

	"github.com/mozilla-services/mozldap"
)

func main() {
	cli, err := mozldap.NewClient(
		os.Getenv("MOZLDAPURI"),
		os.Getenv("MOZLDAPUSER"),
		os.Getenv("MOZLDAPPASSWORD"),
		"",
		&tls.Config{InsecureSkipVerify: true},
		true)
	if err != nil {
		panic(err)
	}
	udns, err := cli.GetUsersInGroups(os.Args[1:])
	if err != nil {
		panic(err)
	}
	for _, udn := range udns {
		shortdn := strings.Split(udn, ",")[0]
		fmt.Printf("\n%s\n", shortdn)
		groups, err := cli.GetGroupsOfUser(shortdn)
		if err != nil {
			panic(err)
		}
		for i, group := range groups {
			fmt.Printf("%d\t%s\n", i, group)
		}
		fmt.Printf("====================================\n")
	}
}
