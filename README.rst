==========
AWS Minion
==========


Installing
==========

Install from PyPI:

.. code-block:: bash

    $ sudo pip3 install aws-minion

Install from source:

.. code-block:: bash

    $ sudo python3 setup.py install

Running
=======

.. code-block:: bash

    $ python3 -m aws_minion # run from source
    $ minion ...            # run installed console script


Example run:

.. code-block:: bash

    $ minion --region eu-west-1 --subnet mysubnet-id --user myuser app create myapp.yaml


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

* ``minion app[lications] ver[sions] traffic my-app 0.1 100%``


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


