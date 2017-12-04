package centrify

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"

	"github.com/centrify/cloud-golang-sdk/oauth"
	"github.com/centrify/cloud-golang-sdk/restapi"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const defaultAuthMode = "ro"

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login",
		Fields: map[string]*framework.FieldSchema{
			"username": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Username of the user.",
			},
			"password": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Password for this user.",
			},
			"mode": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Auth mode ('ro' for resource owner, 'cc' for credential client).",
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation:         b.pathLogin,
			logical.AliasLookaheadOperation: b.pathLoginAliasLookahead,
		},

		HelpSynopsis:    pathLoginSyn,
		HelpDescription: pathLoginDesc,
	}
}

func (b *backend) pathLoginAliasLookahead(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username := strings.ToLower(d.Get("username").(string))
	if username == "" {
		return nil, fmt.Errorf("missing username")
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: username,
			},
		},
	}, nil
}

func (b *backend) pathLogin(
	req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	username := strings.ToLower(d.Get("username").(string))
	password := d.Get("password").(string)
	mode := d.Get("mode").(string)

	if password == "" {
		return nil, fmt.Errorf("missing password")
	}

	if mode == "" {
		mode = defaultAuthMode
	}

	config, err := b.Config(req.Storage)
	if err != nil {
		return nil, err
	}

	var oclient *oauth.OauthClient
	var token *oauth.TokenResponse
	var failure *oauth.ErrorResponse

	if mode == "cc" {
		oclient, err = oauth.GetNewConfidentialClient(config.ServiceURL, username, password, cleanhttp.DefaultClient)
		oclient.SourceHeader = "vault-auth-plugin"
		if err != nil {
			log.Fatal(err)
		}
		token, failure, err = oclient.ClientCredentials(config.AppID, config.Scope)
	} else if mode == "ro" {
		oclient, err = oauth.GetNewConfidentialClient(config.ServiceURL, config.ClientID, config.ClientSecret, cleanhttp.DefaultClient)
		oclient.SourceHeader = "vault-auth-plugin"
		if err != nil {
			log.Fatal(err)
		}
		token, failure, err = oclient.ResourceOwner(config.AppID, config.Scope, username, password)
	} else {
		return nil, fmt.Errorf("Invalid mode or no mode provided: %s", mode)
	}

	if err != nil {
		return nil, err
	}

	if failure != nil {
		return nil, fmt.Errorf("OAuth2 token request failed: %v", failure)
	}

	roleList, err := b.getUsersRoles(token, config.ServiceURL)
	if err != nil {
		return nil, err
	}

	var rolePolicies []string
	if config.RolesAsPolicies {
		for _, role := range roleList {
			rolePolicies = append(rolePolicies, strings.Replace(role, " ", "_", -1))
		}
	}

	resp := &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				"access_token": token,
			},
			Policies: append(config.Policies, rolePolicies...),
			Metadata: map[string]string{
				"username": username,
			},
			DisplayName: username,
			LeaseOptions: logical.LeaseOptions{
				TTL:       time.Duration(token.ExpiresIn) * time.Second,
				Renewable: false,
			},
			Alias: &logical.Alias{
				Name: username,
			},
		},
	}

	for _, role := range roleList {
		resp.Auth.GroupAliases = append(resp.Auth.GroupAliases, &logical.Alias{
			Name: role,
		})
	}

	return resp, nil
}

func (b *backend) getUsersRoles(accessToken *oauth.TokenResponse, serviceUrl string) ([]string, error) {
	restClient, err := restapi.GetNewRestClient(serviceUrl, cleanhttp.DefaultClient)
	if err != nil {
		return nil, err
	}

	restClient.Headers["Authorization"] = accessToken.TokenType + " " + accessToken.AccessToken
	restClient.SourceHeader = "vault-auth-plugin"

	rolesAndRightsResult, err := restClient.CallGenericMapAPI("/usermgmt/GetUsersRolesAndAdministrativeRights", nil)
	if err != nil {
		return nil, err
	}

	var roleList = make([]string, 0)

	if rolesAndRightsResult.Success {
		// Results is an array of map[string]interface{}
		var results = rolesAndRightsResult.Result["Results"].([]interface{})
		for _, v := range results {
			var resultItem = v.(map[string]interface{})
			var row = resultItem["Row"].(map[string]interface{})
			roleList = append(roleList, row["Name"].(string))
			// strings.Replace(row["Name"].(string), " ", "_", -1)
		}
	} else {
		return nil, errors.New(rolesAndRightsResult.Message)
	}

	return roleList, nil
}

const pathLoginSyn = `
Log in with a username and password.
`

const pathLoginDesc = `
This endpoint authenticates using a username and password against the Centrify Identity Services Platform.
`
