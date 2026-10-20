# tesla_fleet_api

Provides a command line interface and an authentication server to allow
access to the Tesla Fleet API.  This can be used to request data and
send commands to the Tesla Fleet API.  The external requirements are a
small as possible with the goal of being zero cost.  However, it does
not directly support the Tesla Fleet Telemetry streaming protocol (which
requires more extensive server setup and more external requirements).

# Requirements

The ultimate goal of the scripts is to provide a zero cost mechanism
to communicate with a Tesla vehicle (now that the Tesla Owner API has
been shut down).  There are no third party app costs, hosting costs,
domain costs or API costs.  However, there are a number of requirements
necessary to achieve this:

- If you don't want to set up a more public server, you must be willing to
  setup a free account with ngrok (or similar service) and open a tunnel to a
  single port to your server.  There will be one file (a public key) that will
  be publicly available and some HTTPS endpoints for OAuth2 that will be
  restricted to your own IP address (i.e. not public accessible).
- You need to keep your requests under the thresholds for free requests for the Tesla
  Fleet API and ngrok.  This is quiet doable with a reasonable polling strategy.
  If you want frequently updated data you can either not poll extremely frequently
  or do intelligent polling where you don't poll frequently when the car is sleeping
  or doing something less interesting.  In my case, I use when my garage door has
  opened to start polling more frequently and HomeLink (as a presence sensor) to
  determine if my vehicle is parked at home or away from home (which will change to
  polling interval significantly).
- You need to install Ruby on your server.

# Functions

Three programs are provided that do the following:

- A CLI tool that allows making requests from the command line.
- An authentication server that provides the OAuth2 communication flow that
  provides an access token needed for the Fleet API endpoints.  The program
  handles refreshing the token so that you only have to log in once.
- A tool to package up vehicle data from the CLI and publish it to MQTT (for
  integration with home automation systems and such).  Note that the script
  only publishes vehicle data received from Tesla.  Commands can't be
  sent, via MQTT, to Tesla.

Additionally, a Ruby class is available if you want to write your own custom
programs as opposed to simply using the CLI tool.

# Use case

In my particular case, I use these scripts to integrate data from my vehicle
into the OpenHAB home automation system.  Rules in OpenHAB control how
frequently I poll for data and act upon the data.  I have automations that
show me my Tesla charge level, report on low tire pressure, let me know when
the vehicle is coming home and let me know when charging is complete.  The
rules are provided in the openhab directory as an example.  They can be
adapted to whatever system you use.

# Inspiration

These scripts were inspired by a project created by QC Tesla Guy.  Check out
his git repo and his YouTube video.  His repo and video shows screenshots of
the Tesla setup and may help with some of the basic setup details.

- https://github.com/qcteslaguy/tesla-fleet-api-demo
- https://www.youtube.com/watch?v=qd6MdAgsOrM

# Prerequisites

- Linux or other operating system (instructions are for a Debian based Linux)
- Ruby
- MQTT server (if you choose to use MQTT)

# External services

- Tesla Fleet API account
- ngrok (or other method to provide a public key and OAuth2 endpoints the
  Tesla Fleet API needs)

# References

- https://developer.tesla.com
- https://developer.tesla.com/docs/fleet-api
- https://developer.tesla.com/docs/fleet-api/announcements
- https://ngrok.com

# Installation

## Things to fill in
In the following instructions and sample files, you will see text like
```_SOME_STRING_``` (starting and ending with underscore).  Replace this
with the appropriate value from your setup.

## Install application
```
apt install ruby ruby-bundler
cd to where you want to install the application (such as /usr/local)
git clone https://tesla_fleet_api.github.com
cd tesla_fleet_api
rake bundle
```

## Create public key
```
rake make_keys
```

## Create ngrok account and endpoint

```
Go to https://ngrok.com and create an account.
Where do you want to start? Put your local app on a public URL [Get Started]
Select Your Authtoken on the left menu
  Make note of the authtoken shown on this page.
  Will be referred to as _YOUR_NGROK_AUTHTOKEN_ below
Select Domains on the left menu
  Make a note of the domain name listed (something like XXX-XXX-XXX.ngrok-free.dev).
  It will be referred as _YOUR_NGROK_DOMAIN_ below
Select Endpoints on the left menu
  [+ New Endpoint]
    How will this endpoint be deployed: Cloud Endpoint
    Where do you want your endpoint to be available: Public
    Choose your URL: https://_YOUR_NGROK_DOMAIN_
    Do you want to allow pooling? Don't allow pooling
    Do you want to add your own traffic policy? Start with a default traffic policy
    [Create endpoint]
```

## Install and configure ngrok
See https://ngrok.com/download for the latest installation instructions for
your operating system.

```
cd tesla_fleet_api

curl -sSL https://ngrok-agent.s3.amazonaws.com/ngrok.asc \
  |  sudo tee /etc/apt/trusted.gpg.d/ngrok.asc >/dev/null \
  && echo "deb https://ngrok-agent.s3.amazonaws.com bookworm main" \
  |  sudo tee /etc/apt/sources.list.d/ngrok.list \
  && sudo apt update \
  && sudo apt install ngrok

ngrok config add-authtoken _YOUR_NGROK_AUTHTOKEN_

cp /home/_YOUR_USER_NAME_/.config/ngrok/ngrok.yml config/ngrok.yaml
```

Optionally, edit config/ngrok.yaml and add the following to the
agent section to allow monitoring ngrok with a web browser at
http://```_YOUR_INTERNAL_IP_ADDRESS_```:4040

```
web_addr: "0.0.0.0:4040"
```

If you have a static or relatively stable internet IP address provided
by your ISP, you can limit access, with an ngrok traffic policy, to
your server's authentication endpoint.  In that case you will only be
able to login to your service from a browser inside your home network
(as opposed to from a mobile network or other external location).
There are other protections in place to prevent malicious actors.  But,
this adds an additional safety layer.  If you don't want to set this up,
remove the restrict-ips section of the ngrok_tesla_policy.yaml file.

To add the network restriction, edit config/ngrok_tesla_policy.yaml

- Replace ```_YOUR_INTERNET_IP_ADDRESS_``` with your external IP address.

Test to see if ngrok is working

```
ngrok http 8089 --config config/ngrok.yaml --traffic-policy-file config/ngrok_tesla_policy.yaml
```

## Create tesla developer account and fleet API application
```
https://developer.tesla.com
  Create a developer account
  Create Fleet API Application
    Registration
      Registration Type: Just for me
    Application Details
      Application Name: Retrieve Car Data (can’t have Tesla in the name)
      Application Description: Retrieve Car Data
      Purpose of Usage: Retrieve Car Data
      [Next]
    Client Details
      OAuth Grant Type: Authorization Code and Machine-to-Machine
      Allowed Origin URL(s): https://_YOUR_NGROK_DOMAIN_
      Allowed Redirect URI(s): https://_YOUR_NGROK_DOMAIN_/auth/callback
      Allowed Returned URL(s) (Optional): 
      [Next]
    API & Scopes
      Fleet API
        Profile Information
        Vehicle Information
        Vehicle Location
        Vehicle Commands            (select only if you want to send commands)
        Vehicle Charging Management (select only if you want to manage charging)
      [Next]
    Billing Details (Optional, will have $10/month credit)
      [Skip and Submit]
```

## View your Tesla client ID and client secret
```
https://developer.tesla.com/en_US/dashboard
  Developer Applications
    "Retrieve Car Data"
      [View Details]
 Credentials & APIs:
   Client ID: _YOUR_TESLA_CLIENT_ID_
   Client Secret: _YOUR_TESLA_CLIENT_SECRET_
```

## Add third-party virtual key to vehicle
- Go to URL on desktop web browser: http://tesla.com/_ak/```_YOUR_NGROK_DOMAIN_```
- Ensure tesla app is logged in on phone
- Scan QR code with phone camera
  - Click scanned link
  - Allow third-party access to this vehicle? [Approve]

## Configure application
Generate a random session secret string to put in the config file (```_YOUR_SESSION_SECRET_```)

```
openssl rand -hex 32
```

Edit config/tesla_api.json

- Replace all of the ```_SOME_STRING_``` strings with values identified above.
- Add any optional settings, as desired.

You need to fill in the following:

| Setting | Description |
| - | - |
| public_host    | Host name ngrok provides |
| client_id      | Client ID that Tesla provides |
| client_secret  | Client secret that Tesla provides |
| session_secret | Session secret (generate with: openssl rand -hex 32) |
| vin            | The Tesla VINs for your vehicles (comma separated) |

The following optional settings can be made:

| Setting | Default |
| - | - |
| local_interface | 127.0.0.1 (use 0.0.0.0 for local network access) |
| local_port      | 8089 |
| scopes          | openid offline_access vehicle_device_data vehicle_location user_data vehicle_cmds vehicle_specs |
| tesla_email     | E-mail address to validate against E-mail registered with Tesla for account |
| state_dir       | "state" directory under application directory (or /var/tmp if not present) |
| state_dir_perms | "0700" (octal numbers must be quoted, might need to be opened wider) |
| state_file_perms| "0600" (octal numbers must be quoted, might need to be opened wider) |
| redirect_path   | /auth/callback |
| auth_host       | fleet-auth.prd.vn.cloud.tesla.com |
| api_host        | fleet-api.prd.na.vn.cloud.tesla.com |
| service_user    | root |
| service_group   | root |

If you are not in North America, you will want to change auth_host
and api_host to the most appropriate Tesla servers (see the Tesla
documentation for details).

You can adjust the scope configuration based on what you set up when you set
up your Tesla developer account.
(see https://developer.tesla.com/docs/fleet-api/authentication/overview).

## Start services

```
sudo rake install_services
```

By default, the services will run with user/group of root/root.
Use a more restrictive user/group (in the config file) as you see fit
(recommended).  It is important that the user/group can write to the
state directory (under the application directory or where you configure
it to be).  If you change user/group or state_dir, in the config file,
you will need to redeploy the services again.

## Test web server and ngrok
Go to https://```_YOUR_INTERNET_IP_ADDRESS_``` in a web browser (or use
the domain name setup in ngrok).  You should be able to log into Tesla
and see your vehicle's data.

If you have set local_interface to 0.0.0.0, you can also go to
http://```_YOUR_INTERNAL_IP_ADDRESS_```:8089 to test the
server without going through ngrok.

## Login to tesla
To log into Tesla, run the following command and bring up the URL provided
in a web browser.

```
bin/cli --login-url
```

Or, have the program open the web browser directly:

```
bin/cli --login-browser
```

## Register partner application (public host name) with Tesla
```
bin/cli --register
```

## Test retrieving data

```
bin/cli --wake vehicle_data
```

Note: wake is comparatively expensive, only use when really necessary.

# CLI examples
See the Endpoints section at https://developer.tesla.com/docs/fleet-api for a
complete list of API endpoints and whether they are sent as GET or POST
requests (DELETE requests are not supported).

Full API call and abbreviated API call that do the same thing.

```
bin/cli /api/1/vehicles
bin/cli vehicles
```

Different ways to abbreviate a vehicle data request.  If "&#123;vin&#125;" is in your
request, your vehicle ID from the config file (or --vehicle-id parameter)
is substituted.

```
bin/cli /api/1/vehicle/_YOUR_VEHICLE_ID_/vehicle_data
bin/cli vehicle/_YOUR_VEHICLE_ID_/vehicle_data
bin/cli vehicle/{vin}/vehicle_data
bin/cli vehicle_data
```

Ways to get multiple sets of vehicle data values.

```
bin/cli 'vehicle_data?endpoints=vehicle_state;location_data'
bin/cli vehicle_state location_data
```

Requesting data for more that one vehicle (still makes 2 API calls).

```
bin/cli --vehicle_ids=111111111111,222222222222 vehicle_data
```

Return vehicle data in a consolidated JSON hash as opposed to an array of
individual JSON responses.

```
bin/cli --consolidated vehicle_state location_data
```

Different ways to send in post data (full JSON, or simple parameters).

```
bin/cli command/actuate_trunk --post-data='{"which_trunk": "front"}'
bin/cli command/actuate_trunk --post-param=which_trunk:front
```

Although the wake_up endpoint is a POST request, you can call it like any
other GET request (i.e. with no post data).
Note that a wake up request takes a few seconds to wake the vehicle up.
Also note that wake_up requests are more expensive than regular requests
in the Tesla Fleet API.
All that said, just use the --wake option instead of wake_up.  This is
mainly an example of a post request with no data.

```
bin/cli wake_up --post-data='{}'
bin/cli wake_up
```

## Sending commands to vehicles

Tesla changed the way commands are sent to the vehicle.  Some of
the examples, above, show the old way via the Fleet REST API
(i.e. command/actuate_trunk).  The newer, encrypted method, involves
building up a message and encrypting it.  It is exposed by the cli
program as follows:

For security actions, you can simply call out the action:

```
bin/cli lock
bin/cli unlock
```

For closure actions, you have to indicate what closable device you want
to change and the action you want it to do:

```
bin/cli front_trunk:open
bin/cli rear_trunk:close
```

The closable devices are:

- front_driver_door
- front_passenger_door
- rear_driver_door
- rear_passenger_door
- rear_trunk
- front_trunk
- charge_port
- tonneau

The action you can perform on them are:

- open
- close
- move
- stop

Only closable devices and actions your vehicle can support are valid.

Added to these, there is a whole series of car service commands to
perform different actions on a vehicle.  To see a list of all of the
different types of supported commands:

```
bin/cli --list
```

## MQTT (optional)
Edit config/mqtt.json

- Fill in the host and port of your MQTT server along with the username and
  password used to connect to the MQTT server.

You can set the following, additional, options if needed for your MQTT server: 

| Setting | Description |
| - | - |
| tls        | Set to true to use TLS connection (will require certificates) |
| key_file   | TLS key file |
| crt_file   | TLS crt file |
| ca_file    | TLS ca file |
| keep_alive | MQTT keep alive in seconds |
| client_id  | ID to uniquely identify client connecting to MQTT server |

Run a poll to collect data from vehicle and publish to MQTT (add --wake
to wake vehicle up if necessary).

```
bin/poll
```

Don't poll too often (i.e. every few seconds or minutes) as you might
use up your free quota for the Tesla Fleet API or ngrok.

For an example of the topics generated, see [OpenHAB things]
(openhab/things/tesla_mqtt.things).

# OpenHAB (Optional)
Since I use OpenHAB for my home automation system, I have included
configuration and rules files for reference.  Even if you don't use
OpenHAB, reviewing the files will help see how you can make use of
these tools.

See [OpenHAB overview] (openhab/README.md) for an overview of the
OpenHAB files.

# Notes
The Tesla auth token generated by the login process will be stored in
the state directory under the application directory.  The Tesla auth
token will be refreshed as necessary. Make sure the state directory is
writable by the user and service running the application.

If you poll for data every few minutes 24/7, you may use up your free
quota with Tesla and ngrok.  Try to poll more efficiently (like only
when the vehicle is being driven).

See [openhab/automation/ruby/tesla_polling.rb]
(openhab/automation/ruby/tesla_polling.rb) for examples on how to
efficiently poll for data.  You may need to adjust the various polling
intervals based on how you use your vehicle.

Your application should retain data from previous polls as opposed to
expecting all data any time you poll.  The vehicle may be asleep and you
won't get fresh data in that case.  You don't want to keep waking the
vehicle up as it is expensive in the Tesla Fleet API and it will run
down your vehicle's battery.  OpenHAB keeps the last received state,
so this is handled automatically in my use case.
