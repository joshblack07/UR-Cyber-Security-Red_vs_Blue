# University of Richmond Cybersecurity Capstone #2

As the Red Team, you will attack a vulnerable VM within your environment, ultimately gaining root access to the machine. As Blue Team, you will use Kibana to review logs taken during their Day 1 engagement. You'll use the logs to extract hard data and visualizations for their report. Then, you will interpret your log data to suggest mitigation measures for each exploit that you've successfully performed.

# Network Topology

The following machines live on the network:

| **Name**     | **IP Address** |
|----------|------------|
| Kali    |  192.168.1.90  |
| Target    | 192.168.1.105   |
|ELK | 192.168.1.100   |


# Red Team
## What were the three most critical vulnerabilities discovered?

While the web server suffers from several vulnerabilities, the three below are the most critical:

  - **Sensitive Data Exposure**: Exposure of the secret_folder directory and the connect_to_corp_server file compromised the credentials of the Web DAV folder. Sensitive Data Exposure (SDE) is an OWASP Top 10 vulnerability.

  - **Unauthorized File Upload**: The web server allows users to upload arbitrary files — specifically, PHP scripts. This exposes the machine to the wide array of attacks enabled by malicious files.

  - **Remote Code Execution**: As a consequence of the unauthorized file upload vulnerability, attackers can upload web shells and achieve arbitrary remote code execution on the web server.

Additional severe vulnerabilities include:

  - Lack of mitigation against brute force attacks
  - No authentication for sensitive data, e.g., secret_folder
  - Plaintext protocols (HTTP and WebDAV)

# Blue Team
## What evidence did you find in the logs of the attack? What data should you be monitoring to detect these attacks in the future?

A considerable amount of data is available in the logs. Specifically, evidence of the following was obtained upon inspection:

  - Traffic from attack VM to target, including unusually high volume of requests
  - Access to sensitive data in the secret_folder directory
  - Brute-force attack against the HTTP server
  - POST request corresponding to upload of shell.php

**Unusual Request Volume**: Logs indicate an unusual number of requests and failed responses between the Kali VM and the target. Note that 401, 301, 207, 404 and 200 are the top responses.

In addition, note the connection spike in the Connections over time [Packetbeat Flows] ECS, as well as the spike in errors in the Errors vs successful transactions [Packetbet] ECS

**Access to Sensitive Data in secret_folder**: On the dashboard you built, a look at your Top 10 HTTP requests [Packetbeat] ECS panel. In this example, this folder was requested 6,197 times. The file connect_to_corp_server was requested 3 times.

**HTTP Brute Force Attack**: Searching for url.path: /company_folders/secret_folder/ shows conversations involving the sensitive data. Specifically, the results contain requests from the brute-forcing toolHydra, identified under the user_agent.original section:



In addition, the logs contain evidence of a large number of requests for the sensitive data, of which only 3 were successful. This is a telltale signature of a brute-force attack. Specifically, the password protected secret_folder was requested 6209 times. However, the file inside that directory was only requested 3 times. So, out of 6209 requests, only 3 were successful.





WebDAV Connection & Upload of shell.php: The logs also indicate that an unauthorized actor was able to access protected data in the webdav directory. The passwd.dav file was requested via GET, and shell.php uploaded via POST.

**Mitigation**: What alarms should you set to detect this behavior next time? What controls should you put in place on the target to prevent the attack from happening?


**Solution**: Mitigation steps for each vulnerability above are provided below.


  * High Volume of Traffic from Single Endpoint

    * Rate-limiting traffic from a specific IP address would reduce the web server's susceptibility to DoS conditions, as well as provide a hook against which to trigger alerts against suspiciously suspiciously fast series of requests that may be indicative of scanning.



  * Access to sensitive data in the secret_folder directory

    * First, the secret_folder directory should be protected with stronger authentication. E.g., it could be moved to a server to which only key-based SSH access from whitelisted IPs is enabled.
    * Second, the data inside of secret_folder should be encrypted at rest.
    * Third, Filebeat should be configured to monitor access to the secret_folder directory and its contents.
    * Fourth, access to secret_folder should be whitelisted, and access from IPs not on this whitelist, logged.



  * Brute-force attack against the HTTP server

    * The fail2ban utility can be enabled to protect against brute force attacks.



  * POST request corresponding to upload of **shell.php**

    * File uploads should require authentication.
    * In addition, the server should implement an upload filter and forbid users from uploading files that may contain executable code.





## Part 2: Incident Analysis with Kibana

After creating your dashboard and becoming familiar with the search syntax, use these tools to answer the questions below:
Identify the offensive traffic.


Identify the traffic between your machine and the web machine:

When did the interaction occur?

  - 11/09/2021  16:00-19:00 PM

What responses did the victim send back?

| HTTP Status Code     | Count |
|----------|------------|
| 401    |  15,981  |
| 301    | 2   |
|200  | 952  |
| 207    | 12   |
|404  | 6  |


What data is concerning from the Blue Team perspective?
  - 15,987 HTTP requests to http://192.168.1.105/company_folders/secrets_folder
  - 2 successful attempts (Code 301)
  - The data above is concerning because it shows repeated unsuccessful transaction attempts, and a spike in unique flow traffic, indicating a possible Brute Force attack.

Find the request for the hidden directory.


In your attack, you found a secret folder. Let's look at that interaction between these two machines.

How many requests were made to this directory? At what time and from which IP address(es)?

  - 15,987 HTTP requests to http://192.168.1.105/company_folders/secrets_folder
  - 11/09/2021  16:00-19:00 PM
  - Source IP: 192.168.1.1

Which files were requested? What information did they contain?

  - The file within the secrets-folder is **connect_to_corp_server**.  
  - This file has ryan’s hashed password as well as other information.

What kind of alarm would you set to detect this behavior in the future?

  - Set an alarm if the folder is accessed

Identify at least one way to harden the vulnerable machine that would mitigate this attack.

  - This directory and file should be removed from the server all together.

Identify the brute force attack.


After identifying the hidden directory, you used Hydra to brute-force the target server. Answer the following questions:
Can you identify packets specifically from Hydra?

  - User_agent.original = Mozilla/4.0 (Hydra)

How many requests were made in the brute-force attack?

  - 15,987 HTTP requests

How many requests had the attacker made before discovering the correct password in this one?

  - 469

What kind of alarm would you set to detect this behavior in the future and at what threshold(s)?

  - Set an alarm based on the threshold for the number of HTTP requests

  - Set an alert when the user_agent.original includes Hydra

Identify at least one way to harden the vulnerable machine that would mitigate this attack.

  - After the limit of 10 401 Unauthorized codes have been returned from a server, that server can automatically drop traffic from the offending IP address for a period of 1 hour. 
  - We could also display a lockout message and lock the page from login for a temporary period of time from that user.

Find the WebDav connection.


Use your dashboard to answer the following questions:
How many requests were made to this directory?

  - 18

Which file(s) were requested?

  - The file that was within 192.168.1.105/webdav/ is shell.php

What kind of alarm would you set to detect such access in the future?
  - Set an alert anytime this directory is accessed by a machine other than the machine that should have access.

Identify at least one way to harden the vulnerable machine that would mitigate this attack.

  - Connections to this shared folder should not be accessible from the web interface.
  - Connections to this shared folder could be restricted by machine with a firewall rule.

Identify the reverse shell and meterpreter traffic.


To finish off the attack, you uploaded a PHP reverse shell and started a meterpreter shell session. Answer the following questions:
Can you identify traffic from the meterpreter session?

  - source.ip: 192.168.1.105 and destination.port: 4444

What kinds of alarms would you set to detect this behavior in the future?

  - We can set an alert for any traffic moving over port 4444.
  - We can set an alert for any .php file that is uploaded to a server.

Identify at least one way to harden the vulnerable machine that would mitigate this attack.
  - Removing the ability to upload files to this directory over the web interface would take care of this issue.

## Group
- [Josh Black](https://github.com/joshblack07)
- [Laura Pratt](https://github.com/laurapratt87)
- [Courtney Templeton](https://github.com/cltempleton1127)
