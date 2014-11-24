==========
AWS Minion
==========

AWS Minion manages immutable Docker application stacks on Amazon EC2 instances with ELB and Route 53.

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

You can run the tool from source or with the installed console script:

.. code-block:: bash

    $ pip3 install -r requirements.txt
    $ python3 -m aws_minion # run from source
    $ minion ...            # run installed console script

You need to configure the AWS region, the AWS VPC and the Route 53 domain before using the tool.

* Create a new VPC in your AWS account.
* Create one or more subnets in the VPC (the VPC wizard does this automatically).
* Configure a new hosted zone/domain (e.g. "apps.example.org") in Route 53.


Example run:

.. code-block:: bash

    $ minion configure
    $ minion app create examples/myapp.yaml
    $ minion ver create myapp 0.1 nginx
    $ minion ver activate myapp 0.1


Running Unit Tests
==================

.. code-block:: bash

    $ python3 setup.py test   # run unit tests
    $ python3 setup.py flake8 # check code formatting


Documentation
=============

See the `AWS Minion Documentation on Read the Docs`_.

Building HTML documentation locally:

.. code-block:: bash

    $ python3 setup.py docs


Workflow
========

* Write application manifest as .yaml file
* Create/register application ``minion app[lications] create mymanifest.yaml``

  * Create security group(s)
  * Registers application in registry (if there, right now storing manifest in tag on security group)

* Push Docker image to your favorite Docker registry
* Register application version ``minion ver[sions] create my-app 0.1 hjacobs/my-app`` (this would use Docker Hub)

  * Create autoscaling group and ELB
  * Start at least one instance (without getting traffic)

* ``minion ver[sions] activate my-app 0.1``

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
    exposed_ports: [80]


ToDos
=====

* use SSL for ELB
* use private and public subnets


.. _AWS Minion Documentation on Read the Docs: http://aws-minion.readthedocs.org/

