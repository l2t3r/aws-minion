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

    $ minion configure
    $ minion app create examples/myapp.yaml
    $ minion app ver create myapp 0.1 nginx
    $ minion app ver activate myapp 0.1


CLI
===

minion module1 submoduleX commandY param1 param2 ..


Workflow
========

* Write application manifest as .yaml file
* Create/register application ``minion app[lications] create mymanifest.yaml``

  * Create security group(s)
  * Registers application in registry (if there, right now storing manifest in tag on security group)

* Push Docker image to your favorite Docker registry
* Register application version ``minion app[lications] ver[sions] create my-app 0.1 hjacobs/my-app`` (this would use Docker Hub)

  * Create autoscaling group and ELB
  * Start at least one instance (without getting traffic)

* ``minion app[lications] ver[sions] activate my-app 0.1``

  * Update DNS to point to version LB


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


