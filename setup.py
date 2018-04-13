from setuptools import setup, find_packages
from audit_pretty import __version__

setup(
    name="audit_pretty",
    version=__version__,
    author="hkettu",
    author_email="hkettu@disroot.org",
    description="Linux Auditing System logs pretty printer",
    license="MIT",
    keywords="utilty linux auditd",
    url="https://github.com/hkettu/audit_pretty",
    packages=find_packages(),
    long_description_content_type='text/markdown',
    entry_points={
        'console_scripts': [
            'audit-pretty = audit_pretty.__main__:main'
        ]
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Topic :: Utilities",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3.5"
    ],
)

