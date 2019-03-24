# savvy-exporter for prometheus

This prometheus export exposes metrics about : 
- processes running (savvy_processes_*)
- apache access logs (savvy_access_log)
- auth log ((savvy_auth_log))

### Processes metrics
Processes running on the host are inspected to expose part of the metrics you would get 
from `top` :
- vmsize memory (savvy_processes_vmsize)
- shared memory (savvy_processes_shared)
- resident memory (savvy_processes_resident)
- percentage of memory used by process (savvy_processes_mem_percent_usage)
- user cpu time
- kernel cpu time

All metrics are labeled with : 
- cmd : the executable name
- cmdline : the full command line running the process
- pid : the process ID
- state : the state of the process (sleeping, running, ...)

### Apache access logs metrics :
The analyzer exposes a simple count of all requests. This analyzer expects access logs to be in `Current` or `Combined` log format.
The metrics are labeled with : 
- ip : the client IP
- method : the HTTP method 
- uri : the uri of the request
- status : the status code of the response
- vhost : the vhost those logs belongs to (based on log filename)

### Auth log metrics:
The analyzer exposes a simple count of all auth attempts.
The metrics are labeled with :
- type : the type of authentication (ssh, sudo, cron)
- success : whether the authentication succeeded or not (true/false)
- username : the user who tries to logged

## How to run it

A systemd service unit file is available in the repo as an example.

