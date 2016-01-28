// List all the groups a given user is a member of

package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/mozilla-services/mozldap"
)

func main() {
	var (
		showUser bool
	)
	cli, err := mozldap.NewClient(
		os.Getenv("MOZLDAPURI"),
		os.Getenv("MOZLDAPUSER"),
		os.Getenv("MOZLDAPPASSWORD"),
		"",
		&tls.Config{InsecureSkipVerify: true},
		true)
	flag.BoolVar(&showUser, "u", false, "Show memberships of a users identified by their ID")
	flag.Parse()
	if len(os.Args) == 0 {
		fmt.Printf("missing groups\nusage: %s <groupid> <groupid>\nusage: %s -u <userid> <userid>",
			os.Args[0], os.Args[0])
		os.Exit(1)
	}
	if err != nil {
		log.Fatal(err)
	}
	var udns []string
	if showUser {
		for _, uid := range flag.Args() {
			dn, err := cli.GetUserDNById(uid)
			if err != nil {
				log.Fatal(err)
			}
			udns = append(udns, dn)
		}
	} else {
		udns, err = cli.GetUsersInGroups(flag.Args())
		if err != nil {
			log.Fatal(err)
		}
	}
	for _, udn := range udns {
		fmt.Printf("\n%s\n", udn)
		groups, err := cli.GetGroupsOfUser(udn)
		if err != nil {
			log.Fatal(err)
		}
		for i, group := range groups {
			fmt.Printf("%d\t%s\n", i, group)
		}
		fmt.Printf("====================================\n")
	}
}
