# cloud-glang-sdk - A Go package and sample library for using the Centrify Cloud Platform API's

The sdk is broken into 3 parts:

  1. sample-app - This is a small CLI utility written in Go which runs a SQL query, meant to serve as an example to using the rest of the sdk
  2. oauth/ - The oauth package is intended to facility initial oauth token retrieval
  3. restapi/ - The restapi package includes a general purpose RestClient for calling Cloud Platform API's
  
SDK Functionality Includes:

  1. Utilizing OAuth2 to create client applications
  2. Sample for issuing queries to the report system
  3. General API consumption via Go

Usage:

  - Requires Go 1.8 or newer
  - Clone this repository
  - Then build and run the sample app:
  ```sh
  cd sample-app
  go build
  ./sample-app -host abc123.my.centrify.com -clientid joe@tenant.com --sql="select ID, DisplayName, Username, Email from User"
  ```

  Note that the sample requires an OAuth2 Client application, default Application ID is "golang_sample", and scope named "all" with REST Regex of at least "redrock/query".  The Application ID and scope names can be overriden on the command line.  A sample template for import has been included in the sample-app/AppTemplate.zip file.  See --help for more:

```sh
$ ./sample-app --help
Usage of ./sample-app:
  -appid string
    	OAuth2 Application ID (default "golang_sample")
  -clientid string
    	OAuth2 Confidential Client ID
  -clientsecret string
    	OAuth2 Confidential Client Secret (if empty, you will be prompted)
  -host string
    	Service URL, i.e. https://<tenantid>.my.centrify.com
  -scope string
    	OAuth2 Scope (default "all")
  -sql string
    	Report query to run (default "select ID, DisplayName, Username, Email from User")
```

Please also note that this requires Centrify Cloud Service version 17.10 or higher for related OAuth2 functionality.