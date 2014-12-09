==========
Quickstart
==========

Prerequisites
=============

* AWS account with at least one VPC
* Route 53 hosted zone
* Recommended: Loggly account
* Python 3.4+ and PIP (``pip3``)

Installation
============

First install Python 3.4 on your PC (Ubuntu 14.04 already has it installed, use Homebrew on Mac).

.. Note::

    OS X users may need to set their locale environment to UTF-8 with::

        export LC_ALL=en_US.utf-8
        export LANG=en_US.utf-8

Install `AWS Minion from PyPI`_:

.. code-block:: bash

    $ sudo pip3 install --upgrade aws-minion

Configuration
=============

Setup AWS Minion configuration:

.. code-block:: bash

    $ minion configure

You need to enter:

* AWS credentials (if you haven't used ``aws`` CLI before) or your SAML credentials (if your AWS account has SAML configured)
* AWS region ID
* AWS VPC ID (might be autodetected)
* Route 53 domain name (might be autodetected)
* SSL Certificate ARN (optional, for HTTPS ELB)
* Loggly credentials (optional)

Use the ``-h`` help flag to find out more about CLI commands and subcommands, e.g. ``minion versions -h``

When using SAML: use ``minion login`` to renew your temporary AWS credentials (they expire after one hour).

.. _creating_an_application:

Creating an Application
=======================

* Write application manifest as .yaml file (see `example manifest`_)

  * Set the "application_name" to your desired app name (e.g. "myapp")
  * Set the "team_name" to your own team name (e.g. "MyTeam/SubTeam")
  * Set the "exposed_ports" to the exposed Docker port(s) (same ports as used in Dockerfile "EXPOSE")

* Create/register application ``minion app[lications] create mymanifest.yaml``

  * This will create security group(s)
  * Registers application in registry (right now storing manifest in tag on security group)

.. image:: _static/cli-app-create.png
   :alt: Screenshot: minion app create

* Push Docker image to your favorite Docker registry
* Register application version ``minion ver[sions] create my-app 0.1 hjacobs/my-app`` (this would use Docker Hub)

  * This will create autoscaling group and ELB
  * Starts at least one instance (without getting traffic)

.. image:: _static/cli-ver-create.png
   :alt: Screenshot: minion ver create

* ``minion ver[sions] traffic my-app 0.1 100``

  * Update DNS to point to version LB

* Access your application at https://myapp.your.configured.domain (use ``http://`` if you haven't configurd any SSL certificate)

.. image:: _static/cli-list.png
   :alt: Screenshot: minion versions and instances


.. _example manifest: https://github.com/zalando/aws-minion/blob/master/examples/myapp-manifest.yaml
.. _AWS Minion from PyPI: https://pypi.python.org/pypi/aws-minion
