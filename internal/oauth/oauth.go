package oauth

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"

	cleanhttp "github.com/hashicorp/go-cleanhttp"
)

// TokenResponse represents successful token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type ErrorResponse struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// OauthClient represents a stateful Oauth client
type OauthClient struct {
	Service      string
	Client       *http.Client
	Headers      map[string]string
	ClientID     string
	ClientSecret string
}

// GetNewClient creates a new client for the specified endpoint
func GetNewClient(service string) (*OauthClient, error) {
	jar, err := cookiejar.New(nil)

	if err != nil {
		return nil, err
	}

	client := &OauthClient{}
	client.Service = service
	client.Client = cleanhttp.DefaultClient()
	client.Client.Jar = jar
	client.Headers = make(map[string]string)
	return client, err
}

// GetNewConfidentialClient creates a new client for the specified endpoint
func GetNewConfidentialClient(service string, clientID string, clientSecret string) (*OauthClient, error) {
	client, err := GetNewClient(service)
	if err != nil {
		return nil, err
	}

	client.ClientID = clientID
	client.ClientSecret = clientSecret
	return client, nil
}

// ResourceOwner implements the ResourceOwner flow
func (c *OauthClient) ResourceOwner(appID string, scope string, owner string, ownerPassword string) (*TokenResponse, *ErrorResponse, error) {
	args := make(map[string]string)
	args["grant_type"] = "password"
	args["username"] = owner
	args["password"] = ownerPassword
	args["scope"] = scope
	return c.postAndGetResponse("/oauth2/token/"+appID, args)
}

func (c *OauthClient) ClientCredentials(appID string, scope string) (*TokenResponse, *ErrorResponse, error) {
	args := make(map[string]string)
	args["grant_type"] = "client_credentials"
	args["scope"] = scope
	return c.postAndGetResponse("/oauth2/token/"+appID, args)
}

func (c *OauthClient) RefreshToken(appID string, refreshToken string) (*TokenResponse, *ErrorResponse, error) {
	args := make(map[string]string)
	args["grant_type"] = "refresh_token"
	args["refresh_token"] = refreshToken
	return c.postAndGetResponse("/oauth2/token/"+appID, args)
}

func (c *OauthClient) postAndGetResponse(method string, args map[string]string) (*TokenResponse, *ErrorResponse, error) {
	body, status, err := c.postAndGetBody(method, args)
	if err != nil {
		return nil, nil, err
	}

	if status == 200 {
		response, err := bodyToTokenResponse(body)
		if err != nil {
			return nil, nil, err
		}
		return response, nil, nil
	}

	response, err := bodyToErrorResponse(body)
	if err != nil {
		return nil, nil, err
	}
	return nil, response, nil
}

func (c *OauthClient) postAndGetBody(method string, args map[string]string) ([]byte, int, error) {
	postdata := strings.NewReader(payloadFromMap(args))
	postreq, err := http.NewRequest("POST", c.Service+method, postdata)

	if err != nil {
		return nil, 0, err
	}

	if c.ClientID != "" && c.ClientSecret != "" {
		postreq.Header.Add("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.ClientID+":"+c.ClientSecret)))
	}

	postreq.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	postreq.Header.Add("X-CENTRIFY-NATIVE-CLIENT", "Yes")
	postreq.Header.Add("X-CFY-SRC", "vault-auth")

	for k, v := range c.Headers {
		postreq.Header.Add(k, v)
	}

	httpresp, err := c.Client.Do(postreq)
	if err != nil {
		return nil, 0, err
	}

	defer httpresp.Body.Close()

	body, err := ioutil.ReadAll(httpresp.Body)
	if err != nil {
		return nil, httpresp.StatusCode, err
	}
	return body, httpresp.StatusCode, nil
}

func payloadFromMap(input map[string]string) string {
	data := url.Values{}
	for i, v := range input {
		data.Add(i, v)
	}
	return data.Encode()
}

func bodyToTokenResponse(body []byte) (*TokenResponse, error) {
	reply := &TokenResponse{}
	err := json.Unmarshal(body, &reply)
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func bodyToErrorResponse(body []byte) (*ErrorResponse, error) {
	reply := &ErrorResponse{}
	err := json.Unmarshal(body, &reply)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
