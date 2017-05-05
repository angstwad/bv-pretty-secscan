from setuptools import setup

setup(
    name='bv-pretty-secscan',
    version='0.1',
    packages=['bv_pretty_secscan'],
    author='Paul Durivage',
    author_email='pauldurivage@gmail.com',
    description='Less sucky formatting of security scan reports',
    install_requires=[
        'ptable',
        'termcolor'
    ],
    entry_points={
        'console_scripts': [
            'bv-pretty-secscan = bv_pretty_secscan.cli:main'
        ]
    }
)
