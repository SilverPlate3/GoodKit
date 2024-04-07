![GoodKit drawio](https://github.com/SilverPlate3/GoodKit/assets/93097769/e7a07a30-1e95-4a65-92a1-d739efa7f3d7)

# project purpose:
Offer blue teams a reliable and efficient way to detect and prevent malicious process's and file aceess.<br>
Users can control the LKM detection rules and exclusion with a simple json.
<br>

# Project state:
**Kernel module** - Fully tested and ready for deployment. More optimizations and capabilities will come in the near future.<br>
**Userspace process** - The real user space process is still under development. At the moment use the UserSpace_poc which offers the reader basic understanding of how the project works. <br>
**Other** - See the NextSteps.txt 

# How to use
```
git clone
sudo make all
sudo ./UserSpace_POC/user_app_poc
```

### Tested and built on
Built on kernel version: 6.5.0-26-generic <br>
Tested on kernel version: 6.5.0-26-generic <br>
Tested on distro: Ubuntu 22.04.3 LTS <br>
GCC version: 12.3.0 <br>

