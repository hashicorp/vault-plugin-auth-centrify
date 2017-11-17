package centrify

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"client_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "OAuth2 Client ID",
			},
			"client_secret": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "OAuth2 Client Secret",
			},
			"service_url": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Service URL (https://<tenant>.my.centrify.com)",
			},
			"app_id": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "OAuth2 App ID",
				Default:     "vault_io_auth",
			},
			"scope": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "OAuth2 App Scope",
				Default:     "vault_io_auth",
			},
			"policies": &framework.FieldSchema{
				Type:        framework.TypeCommaStringSlice,
				Description: "Comma-separated list of policies all authenticated users inherit",
				Default:     []string{"centrify"},
			},
			"roles_as_policies": &framework.FieldSchema{
				Type:        framework.TypeBool,
				Description: "Use user's role list as policies, note that _ will be used in place of spaces.",
				Default:     false,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathConfigCreateOrUpdate,
			logical.CreateOperation: b.pathConfigCreateOrUpdate,
			logical.ReadOperation:   b.pathConfigRead,
		},

		HelpSynopsis: pathSyn,
	}
}

func (b *backend) pathConfigCreateOrUpdate(
	req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	config, err := b.Config(req.Storage)
	if err != nil {
		return nil, err
	}

	val, ok := data.GetOk("client_id")
	if ok {
		config.ClientID = val.(string)
	} else if req.Operation == logical.CreateOperation {
		config.ClientID = data.Get("client_id").(string)
	}
	if config.ClientID == "" {
		return logical.ErrorResponse("config parameter `client_id` cannot be empty"), nil
	}

	val, ok = data.GetOk("client_secret")
	if ok {
		config.ClientSecret = val.(string)
	} else if req.Operation == logical.CreateOperation {
		config.ClientSecret = data.Get("client_secret").(string)
	}
	if config.ClientSecret == "" {
		return logical.ErrorResponse("config parameter `client_secret` cannot be empty"), nil
	}

	val, ok = data.GetOk("service_url")
	if ok {
		config.ServiceURL = val.(string)
	} else if req.Operation == logical.CreateOperation {
		config.ServiceURL = data.Get("service_url").(string)
	}
	if config.ServiceURL == "" {
		return logical.ErrorResponse("config parameter `service_url` cannot be empty"), nil
	}

	val, ok = data.GetOk("app_id")
	if ok {
		config.AppID = val.(string)
	} else if req.Operation == logical.CreateOperation {
		config.AppID = data.Get("app_id").(string)
	}
	if config.AppID == "" {
		config.AppID = "vault_io_auth"
	}

	val, ok = data.GetOk("scope")
	if ok {
		config.Scope = val.(string)
	} else if req.Operation == logical.CreateOperation {
		config.Scope = data.Get("scope").(string)
	}
	if config.Scope == "" {
		config.Scope = "vault_io_auth"
	}

	val, ok = data.GetOk("roles_as_policies")
	if ok {
		config.RolesAsPolicies = val.(bool)
	} else if req.Operation == logical.CreateOperation {
		config.RolesAsPolicies = data.Get("roles_as_policies").(bool)
	}

	if len(config.ServiceURL) != 0 {
		_, err := url.Parse(config.ServiceURL)
		if err != nil {
			return logical.ErrorResponse(fmt.Sprintf("Error parsing given base_url: %s", err)), nil
		}
	}

	// Munge on the service a little bit, force it to have no trailing / and always start with https://
	var normalizedService = strings.TrimPrefix(config.ServiceURL, "http://")
	normalizedService = strings.TrimPrefix(normalizedService, "https://")
	normalizedService = strings.TrimSuffix(normalizedService, "/")
	normalizedService = "https://" + normalizedService
	config.ServiceURL = normalizedService

	entry, err := logical.StorageEntryJSON("config", config)

	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.Config(req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, fmt.Errorf("configuration object not found")
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"client_id":         config.ClientID,
			"client_secret":     config.ClientSecret,
			"service_url":       config.ServiceURL,
			"app_id":            config.AppID,
			"scope":             config.Scope,
			"roles_as_policies": config.RolesAsPolicies,
		},
	}
	return resp, nil
}

// Config returns the configuration for this backend.
func (b *backend) Config(s logical.Storage) (*config, error) {
	entry, err := s.Get("config")
	if err != nil {
		return nil, err
	}

	var result config
	if entry != nil {
		if err := entry.DecodeJSON(&result); err != nil {
			return nil, fmt.Errorf("error reading configuration: %s", err)
		}
	}

	return &result, nil
}

type config struct {
	ClientID        string   `json:"clientID" structs:"clientID" mapstructure:"clientID"`
	ClientSecret    string   `json:"clientSecret" structs:"clientSecret" mapstructure:"clientSecret"`
	ServiceURL      string   `json:"serviceUrl" structs:"serviceUrl" mapstructure:"serviceUrl"`
	AppID           string   `json:"appID" structs:"appID" mapstructure:"appID"`
	Scope           string   `json:"scope" structs:"scope" mapstructure:"scope"`
	Policies        []string `json:"policies" structs:"policies" mapstructure:"policies"`
	RolesAsPolicies bool     `json:"rolesAsPolicies" structs:"rolesAsPolicies" mapstructure:"rolesAsPolicies"`
}

const pathSyn = `
This path allows you to configure the centrify auth provider to interact with the Centrify Identity Services Platform
for authenticating users.  
`
