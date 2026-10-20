The code in this directory implements Tesla's signed_command protocol for
sending commands to a vehicle.  This code handles things like lock/unlock
and open/close commands.  Tesla documents indicate the signed_command
protocol is not supported for Pre-2021 Model S and Model X.  Use the
standard Fleet API REST calls for those vehicles.

Due to the encryption needed, the code in this directory is more intense
than the rest of the code in this package.

The code in this directory was mostly written mostly by AI (ChatGPT),
with a fair amount of human help.  Any changes can be assisted by AI
(i.e. implement additional features or changes in protocol).  The AI
referred to https://github.com/teslamotors/vehicle-command and thus it's
license (Apache License Version 2.0) should be respected, as appropriate.
