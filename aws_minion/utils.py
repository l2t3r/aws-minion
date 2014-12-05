from distutils.version import LooseVersion
from click.types import FloatParamType


class FloatRange(FloatParamType):
    """A parameter that works similar to :data:`click.FLOAT` but restricts
    the value to fit into a range.  The default behavior is to fail if the
    value falls outside the range, but it can also be silently clamped
    between the two edges.
    """
    name = 'float range'

    def __init__(self, min=None, max=None, clamp=False):
        self.min = min
        self.max = max
        self.clamp = clamp

    def convert(self, value, param, ctx):
        rv = FloatParamType.convert(self, value, param, ctx)
        if self.clamp:
            if self.min is not None and rv < self.min:
                return self.min
            if self.max is not None and rv > self.max:
                return self.max
        if self.min is not None and rv < self.min or \
           self.max is not None and rv > self.max:
            if self.min is None:
                self.fail('%s is bigger than the maximum valid value '
                          '%s.' % (rv, self.max), param, ctx)
            elif self.max is None:
                self.fail('%s is smaller than the minimum valid value '
                          '%s.' % (rv, self.min), param, ctx)
            else:
                self.fail('%s is not in the valid range of %s to %s.'
                          % (rv, self.min, self.max), param, ctx)
        return rv

    def __repr__(self):
        return 'FloatRange(%r, %r)' % (self.min, self.max)


class ComparableLooseVersion(LooseVersion):
    """
    "Safe" LooseVersion, which allows comparing versions with mixed str/int components without raising an error.

    >>> ComparableLooseVersion('0.1') == '0.1'
    True

    >>> ComparableLooseVersion('0.1') < '0.2'
    True

    >>> ComparableLooseVersion('0.1.a') == '0.1.1'
    True

    >>> ComparableLooseVersion('0.1.a') < '0.1.1'
    False

    >>> ComparableLooseVersion('0.1.a') > '0.1.1'
    False
    """

    def _cmp(self, other):
        if isinstance(other, str):
            other = ComparableLooseVersion(other)

        if self.version == other.version:
            return 0
        try:
            if self.version < other.version:
                return -1
            if self.version > other.version:
                return 1
        except TypeError:
            # TypeError: unorderable types: str() < int()
            # => just don't care!
            return 0
