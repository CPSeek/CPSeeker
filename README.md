# CPSeeker
A prototype of Memory-like function seeker (CPSeeker), a hybrid (static analysis and dynamic analysis) analysis method that identifies the memory copy function in the (stripped) binary executables.


# Research paper

We present our approach and findings of this work in the following research paper: <br>
<strong> Memcpy-Like Function Identification Method with Static and Dynamic Hybrid Analysis </strong> (reviewing)

# Running environment

Te run code in this repository, you need the IDA Pro (version 7.5) with Python3 support, [Unicorn (1.0.2rc4)](https://github.com/unicorn-engine/unicorn), [pyvex](https://github.com/angr/pyvex), networkx.


# Running example
CPSeeker provides two modes of operation, analysis of a single function and analysis of the entire binary program. The single function analysis is as follows:<br>
![single](single.png "Single mode")
<br>
The output result is:<br>
![output](output.png "Single mode")


# Future work

We will update it to support PowerPC. Unicorn did not support the PowerPC architecture when we implemented CPSeeker, but now it does. Subsequently, we will upgrade the Unicorn version.
