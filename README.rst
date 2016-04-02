========
Overview
========

.. start-badges

.. list-table::
    :stub-columns: 1

    * - docs
      - |docs|
    * - tests
      - | |travis| |appveyor| |requires|
        | |codecov|
        |
    * - package
      - |version| |downloads| |wheel| |supported-versions| |supported-implementations|

.. |docs| image:: https://readthedocs.org/projects/python-omemo/badge/?style=flat
    :target: https://readthedocs.org/projects/python-omemo
    :alt: Documentation Status

.. |travis| image:: https://travis-ci.org/omemo/python-omemo.svg?branch=master
    :alt: Travis-CI Build Status
    :target: https://travis-ci.org/omemo/python-omemo

.. |appveyor| image:: https://ci.appveyor.com/api/projects/status/github/omemo/python-omemo?branch=master&svg=true
    :alt: AppVeyor Build Status
    :target: https://ci.appveyor.com/project/omemo/python-omemo

.. |requires| image:: https://requires.io/github/omemo/python-omemo/requirements.svg?branch=master
    :alt: Requirements Status
    :target: https://requires.io/github/omemo/python-omemo/requirements/?branch=master

.. |codecov| image:: https://codecov.io/github/omemo/python-omemo/coverage.svg?branch=master
    :alt: Coverage Status
    :target: https://codecov.io/github/omemo/python-omemo

.. |version| image:: https://img.shields.io/pypi/v/python-omemo.svg?style=flat
    :alt: PyPI Package latest release
    :target: https://pypi.python.org/pypi/python-omemo

.. |downloads| image:: https://img.shields.io/pypi/dm/python-omemo.svg?style=flat
    :alt: PyPI Package monthly downloads
    :target: https://pypi.python.org/pypi/python-omemo

.. |wheel| image:: https://img.shields.io/pypi/wheel/python-omemo.svg?style=flat
    :alt: PyPI Wheel
    :target: https://pypi.python.org/pypi/python-omemo

.. |supported-versions| image:: https://img.shields.io/pypi/pyversions/python-omemo.svg?style=flat
    :alt: Supported versions
    :target: https://pypi.python.org/pypi/python-omemo

.. |supported-implementations| image:: https://img.shields.io/pypi/implementation/python-omemo.svg?style=flat
    :alt: Supported implementations
    :target: https://pypi.python.org/pypi/python-omemo


.. end-badges

This is an implementation **OMEMO Multi-End Message and Object Encryption** in Python.


Installation
============

::

    pip install python-omemo

Documentation
=============

https://python-omemo.readthedocs.org/

Development
===========

To set up `python-omemo` for local development:

1. `Fork python-omemo on GitHub <https://github.com/omemo/python-omemo/fork>`_.
2. Clone your fork locally::

    git clone git@github.com:your_name_here/python-omemo.git

3. Create a branch for local development::

    git checkout -b name-of-your-bugfix-or-feature

   Now you can make your changes locally.

4. Run all the checks, doc builder and spell checker with `tox <http://tox.readthedocs.org/en/latest/install.html>`_ one command::

    tox

Tips
----

To run a subset of tests::

    tox -e envname -- py.test -k test_myfeature

To run all the test environments in *parallel* (you need to ``pip install detox``)::

    detox


Contributing
============

The **Python OMEMO** project direction is the sum of documented problems:
everybody is invited to describe and discuss a problem in the `issue
tracker <https://github.com/omemo/python-omemo/issues>`_. Contributed solutions

encourage participation.

Some problem fields we initially focus on are:

- Creation of a reusable python omemo implementation
- Reusability bu the `Gajim OMEMO plugin <https://github.com/omemo/gajim-omemo>`_

       
