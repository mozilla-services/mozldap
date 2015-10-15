package mozldap

import (
	"crypto/tls"
	"fmt"
	"regexp"
	"strconv"

	"gopkg.in/ldap.v2"
)

type Client struct {
	conn        *ldap.Conn
	Host        string
	Port        int
	UseTLS      bool
	UseStartTLS bool
	BaseDN      string
}

// NewClient initializes a ldap connection to a given URI. if tlsconf is nil, sane
// default are used (tls1.2, secure verify, ...).
func NewClient(uri, username, password string, tlsconf *tls.Config, starttls bool) (cli Client, err error) {
	cli, err = ParseUri(uri)
	if err != nil {
		return
	}
	if tlsconf == nil {
		// sensible default for TLS configuration
		tlsconf = &tls.Config{
			MinVersion: tls.VersionTLS12,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			},
			InsecureSkipVerify: false,
			ServerName:         cli.Host,
		}
	}
	if cli.UseTLS {
		cli.conn, err = ldap.DialTLS("tcp",
			fmt.Sprintf("%s:%d", cli.Host, cli.Port),
			tlsconf)
	} else {
		cli.conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", cli.Host, cli.Port))
	}
	if err != nil {
		return
	}
	// TLS and StartTLS are mutually exclusive
	if !cli.UseTLS && starttls {
		cli.UseStartTLS = true
		err = cli.conn.StartTLS(tlsconf)
		if err != nil {
			cli.conn.Close()
			return
		}
	}
	// First bind with a read only user
	err = cli.conn.Bind(username, password)
	return
}

// format: ldaps://example.net:636/dc=example,dc=net
const URIRE = "ldap(s)?://(.+):?([0-9]{1,5})?/(.+)"
const URIFORMAT = "ldaps://ldap.example.net:636/dc=example,dc=net"

// ParseUri extracts connection parameters from a given URI and return a client
// that is ready to connect. This shouldn't be called directly, use NewClient() instead.
func ParseUri(uri string) (cli Client, err error) {
	urire := regexp.MustCompile(URIRE)
	fields := urire.FindStringSubmatch(uri)
	if fields == nil || len(fields) != 5 {
		return cli, fmt.Errorf("failed to parse URI. format is '%s'", URIFORMAT)
	}
	// tls or not depends on "s"
	if fields[1] == "s" {
		cli.UseTLS = true
	}
	// get the hostname
	if fields[2] == "" {
		return cli, fmt.Errorf("missing host in URI. format is '%s'", URIFORMAT)
	}
	cli.Host = fields[2]
	// get the port or use default ports
	if fields[3] == "" {
		if cli.UseTLS {
			cli.Port = 636
		} else {
			cli.Port = 389
		}
	} else {
		cli.Port, err = strconv.Atoi(fields[2])
		if err != nil {
			return cli, fmt.Errorf("invalid port in uri. format is '%s'", URIFORMAT)
		}
	}
	// get the base DN
	if fields[4] == "" {
		return cli, fmt.Errorf("missing base DN in URI. format is '%s'", URIFORMAT)
	}
	cli.BaseDN = fields[4]
	return
}

// Search runs a search query against the entire subtree of the LDAP base DN
func (cli *Client) Search(base, filter string, attributes []string) (entries []ldap.Entry, err error) {
	if base == "" {
		base = cli.BaseDN
	}
	searchRequest := ldap.NewSearchRequest(
		cli.BaseDN,             // base dn
		ldap.ScopeWholeSubtree, // scope
		ldap.NeverDerefAliases, // deref aliases
		0,          // size limit
		0,          // time limit
		false,      // types only
		filter,     // search filter
		attributes, // return attributes
		nil)        // controls
	sr, err := cli.conn.Search(searchRequest)
	if err != nil {
		return
	}
	for _, entry := range sr.Entries {
		entries = append(entries, *entry)
	}
	return
}

// GetUserSSHPublicKeys returns a list of public keys defined in a user's sshPublicKey
// LDAP attribute. If no public key is found, the list is empty.
// shortdn is the first part of a distinguished name, such as "mail=jvehent@mozilla.com"
// or "uid=ffxbld". Do not add ,dc=mozilla to the DN.
func (cli *Client) GetUserSSHPublicKeys(shortdn string) (pubkeys []string, err error) {
	entries, err := cli.Search("", "("+shortdn+")", []string{"sshPublicKey"})
	if err != nil {
		return
	}
	for _, entry := range entries {
		for _, attr := range entry.Attributes {
			if attr.Name != "sshPublicKey" {
				continue
			}
			for _, val := range attr.Values {
				pubkeys = append(pubkeys, val)
			}
		}
	}
	return
}

// GetUsersInGroups takes a list of ldap groups and returns a list of unique members
// that belong to at least one of the group. Duplicates are removed, so you only get
// members once even if they belong to several groups.
func (cli *Client) GetUsersInGroups(groups []string) (userdns []string, err error) {
	q := "(|"
	for _, group := range groups {
		q += "(cn=" + group + ")"
	}
	q += ")"
	entries, err := cli.Search("ou=groups,"+cli.BaseDN, q, []string{"member"})
	if err != nil {
		return
	}
	for _, entry := range entries {
		for _, attr := range entry.Attributes {
			if attr.Name != "member" {
				continue
			}
			for _, val := range attr.Values {
				for _, knowndn := range userdns {
					if val == knowndn {
						goto skipit
					}
				}
				userdns = append(userdns, val)
			skipit:
			}
		}
	}
	return
}
