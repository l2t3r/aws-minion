====================
Application Manifest
====================

The **Application Manifest** defines the basic application configuration such as application name, team assignment and exposed port.

.. code-block:: yaml

    ---
    application_name: myapp
    team_name: MyOrganization/MyTeam
    exposed_ports: [8080]
    exposed_protocol: http
    instance_type: t2.micro
    health_check_http_path: /health
    filesystems:
        - type: temporary
          mountpoint: /tmp
          size_mb: 100

AWS Minion stores the application manifest as YAML in the "Manifest" tag on the application's security group (e.g. app-myapp).

Manifest Configuration Keys
===========================

``application_name``
    The application name must follow the regex pattern ``^[a-z][a-z0-9-]{,199}$``.

``team_name``
    Name of the team owning the application.

``exposed_ports``
    List of exposed TCP port numbers.

``exposed_protocol``
    Which protocol is exposed by the application.

    If the exposed protocol is ``http`` the load balancer will expose https in port ``443`` if a certificate was
    provided in the configuration or http in port ``80`` otherwise, and use HTTP health check.

    If the exposed protocol is ``tcp`` the load balancer will expose ``exposed_ports`` and use TCP health check.

``instance_type``
    The EC2 instance type (e.g. ``t2.micro`` or ``m3.large``).

``health-check-http-path``
    HTTP path for HTTP health check mode. Performs GET requests to the given path and waits for status code 200.

``filesystems``
    List of filesystem volumes. Each filesystem must be a map with the keys ``type``, ``mountpoint`` and ``size_mb``.
    "Temporary" filesystems will use the `EC2 Instance Store`_ and mount it under the
    specified ``mountpoint`` (you need to use an instance type with instance store, e.g. ``m3.large``).



.. _EC2 Instance Store: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/InstanceStorage.html


