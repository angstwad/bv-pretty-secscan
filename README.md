# bv-pretty-secscan

If you don't know what this is or does, you probably don't need it.

# Install

No effort has been made for Py3 compatibility.  It might work.  It's not (and won't be) uploaded to PyPI.

```bash
$ pip install git+https://github.com/angstwad/bv-pretty-secscan.git
```

# Use

```
$ bv-pretty-secscan --help
usage: bv-pretty-secscan [-h]
                         [--fields [{IP/Port,Instance,Region,Stack Name,Service,Role,VPC} [{IP/Port,Instance,Region,Stack Name,Service,Role,VPC} ...]]]
                         file

Pretty-printed Bazaarvoice Security Scan Reports

positional arguments:
  file                  Security scan report CSV file to process

optional arguments:
  -h, --help            show this help message and exit
  --fields [{IP/Port,Instance,Region,Stack Name,Service,Role,VPC} [{IP/Port,Instance,Region,Stack Name,Service,Role,VPC} ...]]
                        Limit table to specific columns by column name. Please
                        note that this is case sensitive.
```
