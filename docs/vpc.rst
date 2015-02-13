=================
VPC Configuration
=================

Certain parameters of AWS Minion can be configured on the AWS VPC resource by storing YAML data in a special ``Config`` tag.
See the `AWS documentation on how to use tags`_.
Example tag value might look like:

.. code-block:: yaml

    {
     ami_id: ami-f0b11187,
     registry: docker-registry.example.org
    }

The following global configuration keys can be stored in the ``Config`` tag of the VPC as YAML:

``ami_id``
    The `Amazon Machine Image (AMI)`_ ID to use for EC2 instances.
    This should point to the AMI of Ubuntu 14.04 in your region.

``registry``
    The Docker registry to use (host and port, e.g. "registry.example.org:5000").

.. _AWS documentation on how to use tags: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html
.. _Amazon Machine Image (AMI): http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html
