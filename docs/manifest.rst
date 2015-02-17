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
    root: false
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
    Which protocol is exposed by the application. Valid values are ``http`` and ``tcp`` (default is ``http``):

    If the exposed protocol is ``http``, the load balancer will expose HTTPS on port 443 if a certificate was
    provided in the configuration or plain HTTP on port 80 otherwise. The load balancer will perform a HTTP health check by checking for HTTP status 200.
    Use the ``health_check_http_path`` to configure which HTTP path to check (default is ``/``).

    If the exposed protocol is ``tcp``, the load balancer will expose the first port listed in the ``exposed_ports`` configuration.
    The load balancer will try to perform a TCP connect as health check in this case.

``instance_type``
    The EC2 instance type (e.g. ``t2.micro`` or ``m3.large``). Default is ``t2.micro``.

``health_check_http_path``
    HTTP path for HTTP health check mode. Performs GET requests to the given path and waits for status code 200.
    Default is ``/``.

``root``
    Whether to run the Docker container as "root". Default is false.

``filesystems``
    List of filesystem volumes. Each filesystem must be a map with the keys ``type``, ``mountpoint`` and ``size_mb``.
    "Temporary" filesystems will use the `EC2 Instance Store`_ and mount it under the
    specified ``mountpoint`` (you need to use an instance type with instance store, e.g. ``m3.large``).



.. _EC2 Instance Store: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/InstanceStorage.html


