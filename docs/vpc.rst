=================
VPC Configuration
=================

Certain parameters of AWS Minion can be configured on the AWS VPC resource by storing YAML data in a special ``Config`` tag.
See the `AWS documentation on how to use tags`_.
Example tag value might look like:

.. code-block:: yaml

    {
     ami_id: ami-f0b11187,
     cacerts: ['https://example.org/ca/root.pem', 'https://example.org/ca/service.pem'],
     nameservers: [10.123.1.1, 10.123.1.2],
     registry: docker-registry.example.org
    }

The following global configuration keys can be stored in the ``Config`` tag of the VPC as YAML:

``ami_id``
    The `Amazon Machine Image (AMI)`_ ID to use for EC2 instances.
    This should point to the AMI of Ubuntu 14.04 in your region.

``cacerts``
    List of URLs of additional CA bundles in PEM format to install on EC2 instances.
    This allows using your own private CA bundle or self-signed certificate for your private Docker registry.

``nameservers``
    List of nameservers to use (e.g. "[8.8.8.8]"). This allows using your own private/corporate nameservers.
    This is only a hack as DHCP Options Sets cannot be modified in AWS.

``registry``
    The Docker registry to use (host and port, e.g. "registry.example.org:5000").

``registry_insecure``
    Boolean flag to set ``--insecure-registry`` for dockerd.
    This is only needed if your private Docker registry only provides HTTP.

.. _AWS documentation on how to use tags: http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html
.. _Amazon Machine Image (AMI): http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html
