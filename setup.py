from setuptools import setup

setup(
    name="audit_pretty",
    version="0.0.1",
    author="fox.cpp",
    author_email="fox.cpp@disroot.org",
    description="Linux Auditing System logs pretty printer",
    license="MIT",
    keywords="utilty linux auditd",
    url="https://github.com/foxcpp/audit_pretty",
    packages=["audit_pretty"],
    long_description_content_type='text/markdown',
    entry_points={
        'console_scripts': [
            'audit-pretty = audit_pretty:main'
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

