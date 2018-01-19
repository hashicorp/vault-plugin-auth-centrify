package cps

import (
	"errors"
	"fmt"

	"github.com/centrify/cloud-golang-sdk/restapi"
)

// Encapsulates a single Generic Secret (text only atm)
type Secret struct {
	Name       string
	ID         string
	SecretText string
}

// Encapsulates a single System/server
type System struct {
	Name         string
	ID           string
	Class        string
	HealthStatus string
	FQDN         string
	Description  string
}

// Encapsulates a single CPS Account
type Account struct {
	Name        string
	ID          string
	SystemID    string
	Description string
	Password    string
	Status      string
	Managed     bool
}

// Creates a new secret with the given name/value, returns ID or error
func CreateSecret(client *restapi.RestClient, name string, secret string) (string, error) {
	var funcArg = make(map[string]interface{})
	funcArg["Type"] = "Text"
	funcArg["SecretName"] = name
	funcArg["SecretText"] = secret

	res, err := client.CallStringAPI("/servermanage/adddatavaultitem", funcArg)
	if err != nil {
		return "", err
	}

	if !res.Success {
		return "", errors.New(res.Message)
	}

	return res.Result, nil
}

// Updates a secret with the given value
func UpdateSecret(client *restapi.RestClient, secret Secret, value string) error {
	var funcArg = make(map[string]interface{})
	funcArg["Type"] = "Text"
	funcArg["SecretName"] = secret.Name
	funcArg["SecretText"] = value
	funcArg["ID"] = secret.ID

	res, err := client.CallGenericMapAPI("/servermanage/updatedatavaultitem", funcArg)
	if err != nil {
		return err
	}

	if !res.Success {
		return errors.New(res.Message)
	}

	return nil
}

// Deletes the specified secret by ID
func DeleteSecret(client *restapi.RestClient, id string) error {
	var funcArg = make(map[string]interface{})
	funcArg["ID"] = id

	res, err := client.CallBaseAPI("/servermanage/deletedatavaultitem", funcArg)
	if err != nil {
		return err
	}

	if !res.Success {
		return errors.New(res.Message)
	}

	return nil
}

func GetSecretList(client *restapi.RestClient, includeSecrets bool) (map[string]*Secret, error) {
	// Query for secrets
	var queryArg = make(map[string]interface{})
	queryArg["Script"] = "SELECT * FROM (Select * FROM DataVault ORDER BY SecretName COLLATE NOCASE)"
	var args = make(map[string]interface{})
	args["Caching"] = -1
	args["PageSize"] = 10000
	args["Limit"] = 10000
	queryArg["Args"] = args

	secretListResult, err := client.CallGenericMapAPI("/redrock/query", queryArg)
	if err != nil {
		return nil, err
	}

	// Map of secret name
	var secretList = make([]Secret, 0)
	if secretListResult.Success {
		// Results is an array of map[string]interface{}
		var results = secretListResult.Result["Results"].([]interface{})
		for _, v := range results {
			var resultItem = v.(map[string]interface{})
			var row = resultItem["Row"].(map[string]interface{})
			var secretItem Secret
			secretItem.ID = row["ID"].(string)
			secretItem.Name = row["SecretName"].(string)
			secretList = append(secretList, secretItem)
		}
	} else {
		return nil, errors.New(secretListResult.Message)
	}

	var secretMap = make(map[string]*Secret)
	for i, v := range secretList {
		secretMap[v.Name] = &secretList[i]
	}

	if includeSecrets {
		// Now we know about all the secrets, but dont have secret values, let's get those too
		var fetchArg = make(map[string]interface{})
		for _, v := range secretList {
			fetchArg["ID"] = v.ID
			secretValueResult, err := client.CallGenericMapAPI("/servermanage/retrievedatavaultitemcontents", fetchArg)
			if err != nil {
				return nil, err
			}
			if secretValueResult.Success {
				name := secretValueResult.Result["SecretName"].(string)
				value := secretValueResult.Result["SecretText"].(string)
				secretMap[name].SecretText = value
			} else {
				return nil, errors.New(secretValueResult.Message)
			}
		}
	}

	return secretMap, nil
}

// GetSystemList Gets a list of CPS Systems via RR query
func GetSystemList(client *restapi.RestClient) (map[string]*System, error) {
	var queryArg = make(map[string]interface{})
	queryArg["Script"] = "SELECT Name, ID, HealthStatus, ComputerClass, Description, FQDN FROM Server ORDER BY Name COLLATE NOCASE"
	var args = make(map[string]interface{})
	args["Caching"] = -1
	args["PageSize"] = 10000
	args["Limit"] = 10000
	queryArg["Args"] = args

	serverListResult, err := client.CallGenericMapAPI("/redrock/query", queryArg)
	if err != nil {
		return nil, err
	}

	// Map of secret name
	var systemList = make([]System, 0)
	if serverListResult.Success {
		// Results is an array of map[string]interface{}
		var results = serverListResult.Result["Results"].([]interface{})
		for _, v := range results {
			var resultItem = v.(map[string]interface{})
			var row = resultItem["Row"].(map[string]interface{})
			var systemItem System
			systemItem.ID = row["ID"].(string)
			systemItem.Name = row["Name"].(string)
			systemItem.Class = row["ComputerClass"].(string)
			systemItem.FQDN = row["FQDN"].(string)
			systemItem.HealthStatus = row["HealthStatus"].(string)
			if row["Description"] != nil {
				systemItem.Description = row["Description"].(string)
			}
			systemList = append(systemList, systemItem)
		}
	} else {
		return nil, errors.New(serverListResult.Message)
	}

	var systemMap = make(map[string]*System)
	for i, v := range systemList {
		systemMap[v.Name] = &systemList[i]
	}

	return systemMap, nil
}

// Creates a new system with the given name/value, returns ID or error
func CreateSystem(client *restapi.RestClient, name string, description string, class string, fqdn string) (string, error) {
	var funcArg = make(map[string]interface{})
	funcArg["Name"] = name
	funcArg["Description"] = description
	funcArg["FQDN"] = fqdn
	funcArg["ComputerClass"] = class

	res, err := client.CallStringAPI("/servermanage/addresource", funcArg)
	if err != nil {
		return "", err
	}

	if !res.Success {
		return "", errors.New(res.Message)
	}

	return res.Result, nil
}

// Updates a system with the given value
func UpdateSystem(client *restapi.RestClient, system System) error {
	var funcArg = make(map[string]interface{})
	funcArg["Name"] = system.Name
	funcArg["Description"] = system.Description
	funcArg["FQDN"] = system.FQDN
	funcArg["ComputerClass"] = system.Class
	funcArg["ID"] = system.ID

	res, err := client.CallGenericMapAPI("/servermanage/updateresource", funcArg)
	if err != nil {
		return err
	}

	if !res.Success {
		return errors.New(res.Message)
	}

	return nil
}

// Deletes the specified system by ID
func DeleteSystem(client *restapi.RestClient, id string) error {
	var funcArg = make(map[string]interface{})
	funcArg["ID"] = id

	res, err := client.CallBaseAPI("/servermanage/deleteresource", funcArg)
	if err != nil {
		return err
	}

	if !res.Success {
		return errors.New(res.Message)
	}

	return nil
}

// Get all accounts associated with a specific system
func GetAccountsForSystem(client *restapi.RestClient, systemID string) (map[string]*Account, error) {
	// We can do a join and do it that way, or just get all accounts and filter in memory, for now we use a join...
	var queryFmt = `
		SELECT VaultAccount.ID as ID, VaultAccount.User as User, VaultAccount.Description as Description, Server.ID as SystemID,
			  VaultAccount.Status as Status, VaultAccount.IsManaged as Managed
		FROM Server
		JOIN VaultAccount ON VaultAccount.Host = Server.ID
		WHERE VaultAccount.Host = '%s'
		ORDER BY User COLLATE NOCASE	
	`
	var queryArg = make(map[string]interface{})
	queryArg["Script"] = fmt.Sprintf(queryFmt, systemID)
	var args = make(map[string]interface{})
	args["Caching"] = -1
	args["PageSize"] = 10000
	args["Limit"] = 10000
	queryArg["Args"] = args

	listResult, err := client.CallGenericMapAPI("/redrock/query", queryArg)
	if err != nil {
		return nil, err
	}

	// Map of secret name
	var resList = make([]Account, 0)
	if listResult.Success {
		// Results is an array of map[string]interface{}
		var results = listResult.Result["Results"].([]interface{})
		for _, v := range results {
			var resultItem = v.(map[string]interface{})
			var row = resultItem["Row"].(map[string]interface{})
			var item Account
			item.ID = row["ID"].(string)
			item.Name = row["User"].(string)
			if row["Description"] != nil {
				item.Description = row["Description"].(string)
			}
			if row["IsManaged"] != nil {
				item.Managed = row["IsManaged"].(bool)
			}
			item.SystemID = row["SystemID"].(string)
			item.Status = row["Status"].(string)
			resList = append(resList, item)
		}
	} else {
		return nil, errors.New(listResult.Message)
	}

	var resMap = make(map[string]*Account)
	for i, v := range resList {
		resMap[v.Name] = &resList[i]
	}

	return resMap, nil
}

// Creates a new account with the given name/value, returns ID or error
func CreateAccount(client *restapi.RestClient, systemID string, name string, password string, managed bool, description string) (string, error) {
	var funcArg = make(map[string]interface{})
	funcArg["Host"] = systemID
	funcArg["User"] = name
	funcArg["Password"] = password
	funcArg["IsManaged"] = managed
	funcArg["Description"] = description

	res, err := client.CallStringAPI("/servermanage/addaccount", funcArg)
	if err != nil {
		return "", err
	}

	if !res.Success {
		return "", errors.New(res.Message)
	}

	return res.Result, nil
}

// Updates an existing account with the given name/value, returns ID or error
func UpdateAccount(client *restapi.RestClient, account Account) (string, error) {
	var funcArg = make(map[string]interface{})
	funcArg["ID"] = account.ID
	funcArg["Host"] = account.SystemID
	funcArg["User"] = account.Name
	funcArg["Password"] = account.Password
	funcArg["IsManaged"] = account.Managed
	funcArg["Description"] = account.Description

	res, err := client.CallGenericMapAPI("/servermanage/updateaccount", funcArg)
	if err != nil {
		return "", err
	}

	if !res.Success {
		return "", errors.New(res.Message)
	}

	return res.Result["PVID"].(string), nil
}

// Deletes the specified account by ID
func DeleteAccount(client *restapi.RestClient, id string) error {
	var funcArg = make(map[string]interface{})
	funcArg["ID"] = id

	res, err := client.CallBaseAPI("/servermanage/deleteaccount", funcArg)
	if err != nil {
		return err
	}

	if !res.Success {
		return errors.New(res.Message)
	}

	return nil
}

// Checks out the password for the specified account and returns password
func CheckoutPasswordForAccount(client *restapi.RestClient, id string) (string, error) {
	var funcArg = make(map[string]interface{})
	funcArg["ID"] = id

	res, err := client.CallGenericMapAPI("/servermanage/checkoutpassword", funcArg)
	if err != nil {
		return "", err
	}

	if !res.Success {
		return "", errors.New(res.Message)
	}

	return res.Result["Password"].(string), nil
}

// Checks in the password for the specified account
func CheckinPasswordForAccount(client *restapi.RestClient, id string) error {
	var funcArg = make(map[string]interface{})
	funcArg["ID"] = id

	res, err := client.CallBaseAPI("/servermanage/checkinpassword", funcArg)
	if err != nil {
		return err
	}

	if !res.Success {
		return errors.New(res.Message)
	}

	return nil
}
