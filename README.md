Ansible Playbook - Wazuh agent
==============================

This role will install and configure a Wazuh Agent.

OS Requirements
----------------

This role is compatible with:

 * Red Hat
 * CentOS
 * Fedora
 * Debian
 * Ubuntu


Role Requirements
-----------------

* [ansible-xml](https://github.com/GSA/ansible-xml)

Role Variables
--------------

* `wazuh_agent`: Wazuh agent [local configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/index.html)
  * `wazuh_agent_activeresponse: 'Settings for [active-response](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html) section
  * `wazuh_agent_client`: Settings for [client](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client.html) section
  * `wazuh_agent_clientbuffer`: Settings for [client_buffer](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/client_buffer.html) section
  * `wazuh_agent_labels`: Settings for [labels](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/labels.html) section
  * `wazuh_agent_localfile`: Settings for [localfile](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html) section
  * `wazuh_agent_logformat`: [Log format](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/logging.html#log-format) setting
  * `wazuh_agent_rootcheck`: Settings for [rootcheck](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/rootcheck.html) section
  * `wazuh_agent_socket`: Settings for [socket](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/socket.html) section
  * `wazuh_agent_syscheck`: Settings for [syscheck](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/syscheck.html) section
* `wazuh_authd`: Settings for Wazuh agent [registration](https://documentation.wazuh.com/current/user-manual/registering/index.html)
  * `wazuh_authd_address`: Address of [ossec-authd](https://documentation.wazuh.com/current/user-manual/reference/daemons/ossec-authd.html#ossec-authd) or [ossec-api](https://documentation.wazuh.com/current/user-manual/api/index.html) listener
  * `wazuh_authd_apienable`: Register via [RESTful-API](https://documentation.wazuh.com/current/user-manual/api/reference.html#agents)
  * `wazuh_authd_apihttps`: True if Wazuh API is secured by SSL.
  * `wazuh_authd_apipass`: Password for API [authentication](https://documentation.wazuh.com/current/user-manual/api/configuration.html#basic-authentication)
  * `wazuh_authd_apiport`: API [port](https://documentation.wazuh.com/current/user-manual/api/configuration.html#configuration-file)
  * `wazuh_authd_apiuser`: Username for API [authentication](https://documentation.wazuh.com/current/user-manual/api/configuration.html#basic-authentication)
  * `wazuh_authd_enable`: Register via [authd](https://documentation.wazuh.com/current/user-manual/registering/use-registration-service.html)
  * `wazuh_authd_pass`: Registration [password](https://documentation.wazuh.com/current/user-manual/registering/use-registration-service.html#use-a-password-to-authorize-agents)
  * `wazuh_authd_port`: Port for [ossec-authd](https://documentation.wazuh.com/current/user-manual/reference/daemons/ossec-authd.html#ossec-authd) listener
  * `wazuh_authd_sslauto`: Enable SSL [auto-negotiation](https://documentation.wazuh.com/current/user-manual/reference/tools/agent-auth.html?highlight=negotiate)
  * `wazuh_authd_sslca`: Filename of CA certificate (in `/var/ossec/etc`) used to [verify](https://documentation.wazuh.com/current/user-manual/reference/tools/agent-auth.html?highlight=verify) the server.
  * `wazuh_authd_sslcert`: Filename of [agent certificate](https://documentation.wazuh.com/current/user-manual/reference/tools/agent-auth.html?highlight=-x) (in `/var/ossec/etc`).

Playbook example
----------------

The following is an example of how this role can be used:

```
     - hosts: all:!wazuh-manager
       roles:
         - ansible-wazuh-agent
       vars:
         wazuh_agent_client_server_address: 'wazuh-manager.example.com'
	     wazuh_agent_client_server_protocol: 'tcp'
         wazuh_authd_enable: true
         wazuh_authd_pass: 'S3CR3T'
```

License
-------

BSD

### Based on previouos work by Wazuh inc.

  - https://github.com/wazuh/wazuh-ansible

### Modified by Robert Vincent (robert.vincent@gsa.gov)
