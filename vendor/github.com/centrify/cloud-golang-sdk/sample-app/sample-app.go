package main

import (
	"flag"
	"fmt"
	"log"
	"syscall"

	"github.com/centrify/cloud-golang-sdk/oauth"
	"github.com/centrify/cloud-golang-sdk/restapi"
	"golang.org/x/crypto/ssh/terminal"
)

func main() {
	// Example usage: ./sample-app -host abc123.my.centrify.com -clientid joe@tenant.com
	//	If -clientsecret is not passed, you'll be prompted on stdin

	host := flag.String("host", "", "Service URL, i.e. https://<tenantid>.my.centrify.com")
	appID := flag.String("appid", "golang_sample", "OAuth2 Application ID")
	scope := flag.String("scope", "all", "OAuth2 Scope")
	clientID := flag.String("clientid", "", "OAuth2 Confidential Client ID")
	cliClientSecret := flag.String("clientsecret", "", "OAuth2 Confidential Client Secret (if empty, you will be prompted)")
	query := flag.String("sql", "select ID, DisplayName, Username, Email from User", "Report query to run")
	clientSecret := ""

	flag.Parse()

	// If host or clientid isnt passed, fail
	if *host == "" || *clientID == "" {
		log.Fatalf("You must provide a valid host and clientid")
	}

	// If not passed on command line, prompt for client secret without echoing
	if *cliClientSecret == "" {
		fmt.Print("Enter Client Secret: ")
		passBytes, err := terminal.ReadPassword(int(syscall.Stdin))

		if err != nil {
			log.Fatalf("Unable to read password: %v", err)
		}

		clientSecret = string(passBytes)
	} else {
		clientSecret = *cliClientSecret
	}

	// Get a rest client which has our confidential client's oauth token
	restClient, err := getOauthRestClient(*host, *appID, *scope, *clientID, clientSecret)
	if err != nil {
		log.Fatalf("Unable to get oauth rest client: %v", err)
	}

	// Make a rest call, here we pass a query to be sent to /redrock/query
	outputQueryResult(restClient, *query)

}

func outputQueryResult(restClient *restapi.RestClient, sql string) {
	var queryArg = make(map[string]interface{})
	queryArg["Script"] = sql
	var args = make(map[string]interface{})
	args["Caching"] = -1
	args["PageSize"] = 10000
	args["Limit"] = 10000
	queryArg["Args"] = args

	queryResult, err := restClient.CallGenericMapAPI("/redrock/query", queryArg)
	if err != nil {
		log.Fatalf("Unable to call API: %v", err)
	}

	if queryResult.Success {
		// Results is an array of map[string]interface{}
		log.Printf("Query: \"%s\" - Successful - displaying results:", sql)
		var results = queryResult.Result["Results"].([]interface{})
		for _, v := range results {
			var resultItem = v.(map[string]interface{})
			var row = resultItem["Row"].(map[string]interface{})
			log.Printf("%v", row)
		}
	} else {
		log.Fatalf("Query failed: %s", queryResult.Message)
	}
}

func getOauthRestClient(host string, appID string, scope string, clientID string, clientSecret string) (*restapi.RestClient, error) {
	// Use an oauth client to get our bearer token, currently always via confidential client flow
	token, err := getOauthToken(host, appID, scope, clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	// Then get rest client and set it up to use our token
	restClient, err := getRestClient(host, token)
	if err != nil {
		return nil, err
	}

	return restClient, nil
}

func getRestClient(host string, token *oauth.TokenResponse) (*restapi.RestClient, error) {
	restClient, err := restapi.GetNewRestClient(host, nil)
	if err != nil {
		return nil, err
	}

	restClient.SourceHeader = "golang-sdk-sample"
	restClient.Headers["Authorization"] = token.TokenType + " " + token.AccessToken
	return restClient, nil
}

func getOauthToken(host string, appID string, scope string, clientID string, clientSecret string) (*oauth.TokenResponse, error) {
	oclient, err := oauth.GetNewConfidentialClient(host, clientID, clientSecret, nil)
	if err != nil {
		log.Printf("Unable to get confidential client: %v", err)
		return nil, err
	}
	oclient.SourceHeader = "golang-sdk-sample"
	token, failure, err := oclient.ClientCredentials(appID, scope)

	if err != nil {
		log.Printf("Unable to get confidential client token: %v", err)
		return nil, err
	}

	if failure != nil {
		return nil, fmt.Errorf("Unable to get oauth token, failure: %v", failure)
	}

	log.Printf("Client token established - type: %s expires in: %d", token.TokenType, token.ExpiresIn)
	return token, nil
}
