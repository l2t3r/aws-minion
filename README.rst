===========
AWS "Stuff"
===========

Start a single instance with Docker and ELB:

.. code-block:: bash

    $ ./stuff.py --region eu-west-1 --subnet mysubnet-id --user myuser


CLI
===

minion module1 submoduleX commandY param1 param2 ..


Workflow
========

* Write application manifest as .yaml file
* Create/register application ``minion app[lications] create mymanifest.yaml``

  * Registers application in registry (if there)
  * Create security group(s)
  * Create application ELB and DNS entry

* Push Docker image to your favorite Docker registry
* Register application version ``minion app[lications] ver[sions] create my-app 0.1 hjacobs/my-app`` (this would use Docker Hub)

  * Registers application version in registry (if there)
  * Create application version ELB and DNS entry
  * Start at least one instance (without getting traffic)


minion applications


Manifest
========

.. code-block:: yaml

    ---
    application_name: my-app
    team_name: MyTeam/SubTeam
    accessible_by:
        - my-other-app
        - another-app
    stateful: false


