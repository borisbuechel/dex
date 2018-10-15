package userinfo

import (
	ldap "gopkg.in/ldap.v2"
)

// Userinfo enables all required LDAP operations for a given user.
type Userinfo interface {

	// Close the LDAP connection
	Close()

	// Authenticate a (techuser) against the password stored in the DRD
	// this will authenticate a given userID and password (from the basic auth header from the client credentils flow),
	// and tries an ldap bind against the provided ldap connection.
	// Obviously, this will only work for non-human users, as they have their user password in a different ldap 
	Authenticate(index, userID, userPassword string) error

	// Retrieves user attributes
	// index defines the index string to lookup the provided user search configuration in the dex config file
	// userID defines the userID to lookup
	GetUserInformation(index, userID string) (*ldap.SearchResult, error)
}
