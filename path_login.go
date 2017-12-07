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
				Default:     "ro",
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

	config, err := b.Config(req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, errors.New("centrify auth plugin configuration not set")
	}

	var oclient *oauth.OauthClient
	var token *oauth.TokenResponse
	var failure *oauth.ErrorResponse

	if mode == "cc" {
		oclient, err = oauth.GetNewConfidentialClient(config.ServiceURL, username, password, cleanhttp.DefaultClient)
		oclient.SourceHeader = "vault-plugin-auth-centrify"
		if err != nil {
			log.Fatal(err)
		}
		token, failure, err = oclient.ClientCredentials(config.AppID, config.Scope)
	} else if mode == "ro" {
		oclient, err = oauth.GetNewConfidentialClient(config.ServiceURL, config.ClientID, config.ClientSecret, cleanhttp.DefaultClient)
		oclient.SourceHeader = "vault-plugin-auth-centrify"
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

	uinfo, err := b.getUserInfo(token, config.ServiceURL)
	b.Logger().Trace("centrify authenticated user", "userinfo", uinfo)
	if err != nil {
		return nil, err
	}

	var rolePolicies []string
	if config.RolesAsPolicies {
		for _, role := range uinfo.roles {
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
				"username": uinfo.username,
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

	for _, role := range uinfo.roles {
		resp.Auth.GroupAliases = append(resp.Auth.GroupAliases, &logical.Alias{
			Name: role,
		})
	}

	return resp, nil
}

type userinfo struct {
	uuid     string
	username string
	roles    []string
}

// getUserInfo returns list of user's roles, user uuid, user name
func (b *backend) getUserInfo(accessToken *oauth.TokenResponse, serviceUrl string) (*userinfo, error) {
	uinfo := &userinfo{}

	restClient, err := restapi.GetNewRestClient(serviceUrl, cleanhttp.DefaultClient)
	if err != nil {
		return nil, err
	}

	restClient.Headers["Authorization"] = accessToken.TokenType + " " + accessToken.AccessToken
	restClient.SourceHeader = "vault-plugin-auth-centrify"

	// First call /security/whoami to get details on current user
	whoami, err := restClient.CallGenericMapAPI("/security/whoami", nil)
	if err != nil {
		return nil, err
	}
	uinfo.username = whoami.Result["User"].(string)
	uinfo.uuid = whoami.Result["UserUuid"].(string)

	// Now enumerate roles
	rolesAndRightsResult, err := restClient.CallGenericMapAPI("/usermgmt/GetUsersRolesAndAdministrativeRights", nil)
	if err != nil {
		return nil, err
	}

	uinfo.roles = make([]string, 0)

	if rolesAndRightsResult.Success {
		// Results is an array of map[string]interface{}
		var results = rolesAndRightsResult.Result["Results"].([]interface{})
		for _, v := range results {
			var resultItem = v.(map[string]interface{})
			var row = resultItem["Row"].(map[string]interface{})
			uinfo.roles = append(uinfo.roles, row["Name"].(string))
		}
	} else {
		b.Logger().Error("centrify: failed to get user roles", "error", rolesAndRightsResult.Message)
	}

	return uinfo, nil
}

const pathLoginSyn = `
Log in with a username and password.
`

const pathLoginDesc = `
This endpoint authenticates using a username and password against the Centrify Identity Services Platform.
`
