==========
AWS Minion
==========

.. image:: https://travis-ci.org/zalando/aws-minion.svg?branch=master
   :target: https://travis-ci.org/zalando/aws-minion
   :alt: Build Status

.. image:: https://readthedocs.org/projects/aws-minion/badge/?version=latest
   :target: https://readthedocs.org/projects/aws-minion/?badge=latest
   :alt: Documentation Status

.. image:: https://coveralls.io/repos/zalando/aws-minion/badge.png
   :target: https://coveralls.io/r/zalando/aws-minion
   :alt: Coverage Status

AWS Minion manages immutable Docker application stacks on Amazon EC2 instances with ELB and Route 53.
See the `AWS Minion Documentation on Read the Docs`_.

.. image:: http://aws-minion.readthedocs.org/en/latest/_images/application-stack.svg
   :target: http://aws-minion.readthedocs.org/en/latest/concepts.html
   :alt: Application Stack

AWS Minion requires Python 3.4+ and was only tested on Ubuntu 14.04 and Mac OS X.

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

    $ python3 setup.py test --cov-html=yes  # run unit tests
    $ python3 setup.py flake8               # check code formatting


Documentation
=============

See the `AWS Minion Documentation on Read the Docs`_.

Building HTML documentation locally:

.. code-block:: bash

    $ python3 setup.py docs


ToDos
=====

* use private and public subnets
* fix hardcoded AMI ID
* create new base AMI


.. _AWS Minion Documentation on Read the Docs: http://aws-minion.readthedocs.org/

