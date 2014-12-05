===============
Troubleshooting
===============

How to access your EC2 Instances via SSH
========================================

AWS Minion generates one SSH keypair per application (will be automatically stored in your local SSH folder as ``~/.ssh/app-myapp.pem``). You can login via SSH by finding the instance IP via ``minion instances`` and using the generated keypair:

.. code-block:: bash

    $ minion instances
    $ ssh -i ~/.ssh/app-myapp.pem ubuntu@<INSTANCE-IP>

You can debug the application instance start (Docker run) by looking into ``/var/log/cloud-init-output.log`` on the respective EC2 instance.

Please always mention the AWS Minion version ("minion --version") when reporting problems.


ImportError: cannot import name 'IncompleteRead'
================================================

On Ubuntu, you might get the following error when following the aws-minion installation instructions:

.. code-block:: bash

    $ sudo pip3 install --upgrade aws-minion
    .....
    ImportError: cannot import name 'IncompleteRead'

This can easily be fixed with the following command:

.. code-block:: bash

    $ sudo easy_install3 requests==2.2.1

The main problem is the dependency hell between Debian-packaged Python stuff (python3-* packages) and custom-installed PIP (``pip3 freeze``).
