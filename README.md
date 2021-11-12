# University of Richmond Cybersecurity Capstone #2

  - As the Red Team, I attacked a vulnerable VM, ultimately gaining root access to the machine. 
  - As the Blue Team, I used Kibana to review logs taken during the Red Team Engagement. 
  - I used the logs to extract hard data and visualizations for the report. 
  - Then, I interpreted log data to suggest mitigation measures for each exploit.

[Here](https://github.com/joshblack07/UR-Cyber-Security-Red_vs_Blue/blob/main/Supplemental%20Resources/Capstone%20Engagement%202.pptx "Capstone_PowerPoint") is a PowerPoint Presentation of the Capstone.


# Network Topology

The following machines live on the network:

| **Name**     | **IP Address** |
|----------|------------|
| Kali    |  192.168.1.90  |
| Target    | 192.168.1.105   |
|ELK | 192.168.1.100   |
|Azure Hyper-V ML-RefVm-684427 | 192.168.1.1   |

![alt text](https://github.com/joshblack07/UR-Cyber-Security-Red_vs_Blue/blob/main/Supplemental%20Resources/Network_Diagram.jpg "Network Diagram")


# Red Team
## What were the three most critical vulnerabilities discovered?

While the web server suffers from several vulnerabilities, the three below are the most critical:


| **Vulnerability**     | **Description** | **Impact |
|----------|------------|------------|
| Sensitive Data Exposure OWASP Top 10 #3 Critical | The secret_folder is publicly accessible, but contains sensitive data intended only for authorized personnel. |The exposure compromises credentials that attackers can use to break into the web server.  |
| Unauthorized File Upload Critical  | Users are allowed to upload arbitrary files to the web server.   | This vulnerability allows attackers to upload PHP scripts to the server.  |
|Remote Code Execution via Command Injection OWASP Top 10 #1 Critical | Attackers can use PHP scripts to execute arbitrary shell commands. | Vulnerability allows attackers to open a reverse shell to the server.|

Additional vulnerabilities include:

| **Vulnerability**     | **Description** | **Impact |
|----------|------------|------------|
| Directory Indexing Vulnerability (CWE-548) |  Attacker can view and download content of a directory located on a vulnerable device. CWE-548 refers to an informational leak through directory listing.  | The attacker can gain access to source code, or devise other exploits. The directory listing can compromise private or confidential data.  |
| Hashed Passwords  | If a password is not salted it can be cracked via online tools such as www.crackstation.net/ or programs such as hashcat.  | Once the password is cracked, and if a username is already known, a hacker can access system files.  |
|Weak usernames and passwords | Commonly used passwords such as simple words, and the lack of password complexity, such as the inclusion of symbols, numbers and capitals.  | System access could be discovered by social engineering. https://thycotic.com/resources/password-strength-checker/ suggests that ‘Leopoldo’ could be cracked in 21 seconds by a computer. |
|Port 80 Open with Public Access (CVE-2019-6579) | 192.168.1.1   | Open and unsecured access to anyone attempting entry using Port 80.  | Files and Folders are readily accessible. Sensitive (and secret) files and folders can be found. |
| Ability to discover passwords by Brute Force (CVE-2019-3746) |  When an attacker uses numerous username and password combinations to access a device and/or system. | Easy system access by use of brute force with common password lists such as rockyou.txt by programs such as Hydra  |
| No authentication for sensitive data, e.g., secret_folder |    |   |
|Plaintext protocols (HTTP and WebDAV) |   |

# Blue Team
## What evidence did you find in the logs of the attack? What data should you be monitoring to detect these attacks in the future?

A considerable amount of data is available in the logs. Specifically, evidence of the following was obtained upon inspection:

  - Traffic from attack VM to target, including unusually high volume of requests
  - Access to sensitive data in the secret_folder directory
  - Brute-force attack against the HTTP server
  - POST request corresponding to upload of shell.php

**Unusual Request Volume**: Logs indicate an unusual number of requests and failed responses between the Kali VM and the target. Note that 401, 301, 200, 207, and 404 are the top responses.

| HTTP Status Code | Count |
|----------|------------|
|   401    |   15,981   |
|   301    |     2      |
|   200    |    952     |
|   207    |     12     |
|   404    |     6      |

Time: 11/09/2021  16:00-19:00 PM

In addition, note the connection spike in the Connections over time [Packetbeat Flows] ECS, as well as the spike in errors in the Errors vs successful transactions [Packetbet] ECS

![alt text](https://github.com/joshblack07/UR-Cyber-Security-Red_vs_Blue/blob/main/Supplemental%20Resources/connections%20over%20time%20packetbeat%20flows%20ecs%20today.PNG "connection_spike")

![alt text](https://github.com/joshblack07/UR-Cyber-Security-Red_vs_Blue/blob/main/Supplemental%20Resources/errors%20vs%20successful%20transactions%20packetbeat%20ecs%20today.PNG "errors")

**Access to Sensitive Data in secret_folder**: On the dashboard you built, a look at your Top 10 HTTP requests [Packetbeat] ECS panel. In this example, this folder was requested 15,987 times.

![alt text](https://github.com/joshblack07/UR-Cyber-Security-Red_vs_Blue/blob/main/Supplemental%20Resources/dashboard%20w%20shell.PNG "HTTP_Requests")

**HTTP Brute Force Attack**: Searching for url.path: /company_folders/secret_folder/ shows conversations involving the sensitive data. Specifically, the results contain requests from the brute-forcing tool Hydra, identified under the user_agent.original section:

![alt text](https://github.com/joshblack07/UR-Cyber-Security-Red_vs_Blue/blob/main/Supplemental%20Resources/hydra%20total.PNG "Hydra")

In addition, the logs contain evidence of a large number of requests for the sensitive data, of which only 2 were successful. This is a telltale signature of a brute-force attack. 

  - 15,987 HTTP requests to http://192.168.1.105/company_folders/secrets_folder
  - 2 successful attempts (Code 301)
  - 11/09/2021  16:00-19:00 PM
  - Source IP: 192.168.1.1

![alt text](https://github.com/joshblack07/UR-Cyber-Security-Red_vs_Blue/blob/main/Supplemental%20Resources/what%20data%20is%20concerning.PNG "HTTP_Requests")

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

# Assessment Summary

| **Red Team**     | **Blue Team** |
|----------|------------|
| Accessed the system via HTTP Port 80   |  Confirmed that a port scan occurred  |
| Found Root accessibility  | Found requests for a hidden directory   |
|Found the occurrence of simplistic usernames and weak passwords | Found evidence of a brute force attack |
|Brute forced passwords to gain system access | Found requests to access critical system folders and files |
|Cracked a hashed password to gain system access and use a shell script | Identified a WebDAV vulnerability |
|Identified Directory Indexing Vulnerability CWE-548| Recommended alarms   |
|   |  |  Recommended system hardening |


## Group
- Julian Baker
- Robbie Drescher
- [Josh Black](https://github.com/joshblack07)
- [Laura Pratt](https://github.com/laurapratt87)
- [Courtney Templeton](https://github.com/cltempleton1127)
