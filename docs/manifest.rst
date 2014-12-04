====================
Application Manifest
====================

The **Application Manifest** defines the basic application configuration such as application name, team assignment and exposed port.

.. code-block:: yaml

    ---
    application_name: myapp
    team_name: MyOrganization/MyTeam
    exposed_ports: [8080]
    instance_type: t2.micro
    health_check_http_path: /health

AWS Minion stores the application manifest as YAML in the "Manifest" tag on the application's security group (e.g. app-myapp).

