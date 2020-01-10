# Conserity

A modern security system for secret data in your cloud

For *online* active private secrets

Convenient and secure, for the IT serenity

Free, open-source and collaborative

## The software project

Creates a protected directory in the user home. This protected directory is encrypted and is only clear-text in the server's RAM. This encryption is virtually transparent for performance and the data content.

Additionally, Conserity setups the access and configures the server for maximum security.

The encryption key is not located in the server, but remotely and securely read from others small servers. With the Shamir sharing option, Conserity can automatically setup the remote instances which are holding a share of the encryption secret.

You can easily protect any web application running in a virtual or a dedicated server.

Designed to be run on a fresh new machine, this setups everything for security and protects a user path.

The server can be fully backup or snapshot, and the sensitive data are fully encrypted. The data are protected, there are only exposed inside the server, in RAM, and the access to the server is restricted and secured.

The entire project is collaborative, open and free. All the software and scripts are under [GPLv3 license](https://www.gnu.org/licenses/gpl-3.0.en.html).

Get more info on :
https://conserity.org

## Use cases examples

Can be used to protect the following apps :
* Messaging server (Mastodon, Matrix/Riot, )
* Central software repository (Gitea, GitLab, Gogs, )
* Software CI/CD (Jenkins, Jira, )
* Online electronic document management or editing (Collabora, OnlyOffice, CaseBox, EveryDocs, )
* Collaborative team hub platform workspace (Mattermost, RocketChat, )
* Email or calendar tasks server (Zimbra, Roundcube, )
* Cloud remote desktop (Sandstorm, CloudComputer, )
* Private media gallery (Coppermine, Piwigo, )
* Cloud data storage service (ownCloud, Cozy, NextCloud, )
* Web service (Wordpress, WooCommerce, Joomla, Node, database, )
* Digital content distribution (magazine, integrated library, )
* Keys management (hot key store, PKI, )
* Online processing (Kore.io, fx, APIs, )
* Any self hosted web or online app

## Get and run

#### Prerequisite

A Debian 10 system  
with its IP on a domain

You must create an A record for your domain that points to the IP address of the server instance. If your server is behind a NAT, then you need to forward port # 80 to your instance.

If you choose the Shamir secret split of the encryption key in several remote servers, you need to have and provide a Linode API key.

#### Compatibility

OS : Linux based
* Debian, Ubuntu
* Fedora , CentOS , RHEL  
Only Debian 10 for now.

VPS instance providers :
* DigitalOcean
* Vultr
* Linode
* Scaleway
* AWS
* Potentially any provider which has a docker-machine plugin  
Only Linode for now.

Web services protected :
* internal web server (node, Kore.io, ... )
* PHP (web files)
* WSGI (Python uWSGI, ...)  
Only internal web server for now.

#### Install


```
wget https://codeload.github.com/bitlogik/Conserity/tar.gz/master
tar -xzf master
cd Conserity-master
chmod +x run-conserity.sh
chmod +x getpwd
chmod +x shamir/split_secret.py
chmod +x shamir/recover_secret.py
chmod +x vps-drivers/create-linode.sh
```

or with git

```
apt-get install -y git
git clone https://github.com/BitLogiK/Conserity.git
cd Conserity
```

#### Run

If you plan to use the Shamir split secret, you need to define the LinodeAPIKey bash variable with your Linode APIv4 access token.
```
export LinodeAPIKey=YOURLINODEAPITOKEN ; history -d $(history 1)
```
Else, you just need a single remote Apache web server (a different server from where you install Conserity).


Run Conserity in the main server :

```
./run-conserity.sh
```

Follow the instructions. You can choose :

* User name (created if not exist)
* Size of the protected directory
* Type of setup :
  * Single secret with displayed setting for Apache
  * Shamir split secret, with automatic instances installation
* Type of web service : Web, PHP, UWSGI (Not yet availaible)

Conserity performs the following :

* Update the OS
* Install packages required
* Strengthen Ethernet interfaces configuration
* Setup SSH server for security
* Create and setup a Nginx server (proxy)
* Generate a LetsEncrypt HTTPS certificate (plus its renewal)
* Configure a firewall
* Add a user if needed
* Create all remote secret servers at the instance providers (if Shamir option)
* Create the local encrypted directory
* Setup auto mount at reboot (read remote secrets, mount)

At the end it is advised to reboot, at least to update the kernel version.

If you choose the option to use "one existing remote web server", setup that remote server files as displayed at the end before rebooting.

#### Info

The remote instance names are using an host ID as follow :
```
cat /etc/machine-id | sha256sum | cut -c1-8
```

For now, the remote instances provider (for automatic Shamir install) is Linode.
We plan to add many others providers such as : 
* DigitalOcean
* Vultr
* Scaleway
* AWS

#### Use

After running Conserity, you now have an encrypted directory in /home/*USER*/protected_files. Every single directory and file inside this protected_files is fully protected by Conserity.

Also, the server is secured with infosec best practices (Web server, SSH, firewall,...)

What does it protect ?  
Conserity strengthens your server security and encrypts your data on the disk. It protects against :
* Unauthorized access in your server (more difficult to break in)
* Data read from the disk, or from any backup, disk snapshot,...
* Spying or wiretapping of the web session of the users (web server is configured for security)

What does it NOT protect ?  
It does NOT protect against :
* Authorized legitimate access in the server (rogue employee, accidental deletion,...)
* A present "hole" in the server used softwares (OpenSSL, nginx,...)
* Your own web app leaks, for example if it gives some secrets to anyone
* A user of the web app is hacked/infected, so the data (s)he's reading is leaked.
* Data deletion. Conserity is not a backup system. Nevertheless, it helps to backup, since any data in the protected folder is securely encrypted.

Why is my email address needed ?  
Your email address is asked by certbot for the LetsEncrypt certificate ACME server. This is required to register an account, and useful in the event of server key loss or account compromise, also to receive notices about revocation of your certificates.

Why I get a security alert when I connect again on SSH ? Is it an intermediate system in the link spying or analyzing the data link?  
Absolutely not, you still connect directly to your server SSHd and without anything in the middle. Conserity just generates new SSH keys to be sure the used ones are robust. So the SSH keys are changed and thus eventually triggering an alert about the server has changed its host key.

## Support or Questions

email : support@conserity.org

Join our mailing list by sending an email to 
conserity-request@freelists.org 
with 'subscribe' in the Subject field or  
by visiting http://www.freelists.org/list/conserity

Interested in joining, testing, supporting or developing?  
email : project@conserity.org

## ToDo

* Add more HTTP headers
* Add others web service types : PHP/HTML and WSGI
* Ubuntu compatibility (and then Fedora/CentOS/RHEL)
* Add others VPS providers : Vultr, Scaleway, then DigitalOcean and AWS
