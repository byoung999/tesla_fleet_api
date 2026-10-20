# OpenHAB overview

These files contain my specific OpenHAB configuration.  They will need to
be modified to meet your needs and moved under the /etc/openhab directory.
Or, you can just refer to them as examples of interesting things to do in
whatever environment you have.

Various places in the things, items and rules files have ```_SOME_STRING_```
placeholders that you must replace with values suitable for your situation.

The file in the things directory shows the list of vehicle data MQTT
topics provided by the default configuration of the program.  Also,
tesla may add more data values in the future.  Use as a reference and
adjust as necessary.

The rules are presented as a sample of what you can do.  I happen to use
JRuby for the rules.  However, you can take the ideas presented here and
create rules in whatever language or environment you like.

The rules are broken up into two groups:

- The rules in tesla_polling.rb file are used to manage intelligent polling
of data from the Tesla Fleet API.  It polls more often when something
interesting is happening with the vehicle and less often when the vehicle is
idle.  There are constants defined at the top of the file to control the
polling interval during different stages of operation.  The values there
work well for me.  If you drive very frequently, you may need to change
them to stay within the free thresholds of the Tesla Fleet API and ngrok.
Check their usage pages to see where your usage stands.  Note that there
are some polling rules triggered on things that I have that you might
not (like whether the garage door has been opened or whether Homelink
has been detected).  Adjust as appropriate for your situation.

- The rules in the tesla.rb are used for my home automation system to
do things with data from the Tesla (make announcements and show status
indicators).  These types of rules will be very different for each
person's setup.
