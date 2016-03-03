===================
Intel(R) SGX driver
===================

Introduction
============

Intel(R) SGX is a set of CPU instructions that can be used by applications to
set aside private regions of code and data. The code outside the enclave is
disallowed to access the memory inside the enclave by the CPU access control.
In a way you can think that SGX provides inverted sandbox. It protects the
application from a malicious host.

You can tell if your CPU supports SGX by looking into ``/proc/cpuinfo``:

	``cat /proc/cpuinfo  | grep sgx``

Overview of SGX
===============

SGX has a set of data structures to maintain information about the enclaves and
their security properties. BIOS reserves a fixed size region of physical memory
for these structures by setting Processor Reserved Memory Range Registers
(PRMRR).

This memory range is protected from outside access by the CPU and all the data
coming in and out of the CPU package is encrypted by a key that is generated for
each boot cycle.

Enclaves execute in ring-3 in a special enclave submode using pages from the
reserved memory range. A fixed logical address range for the enclave is reserved
by ENCLS(ECREATE), a leaf instruction used to create enclaves. It is referred in
the documentation commonly as the ELRANGE.

Every memory access to the ELRANGE is asserted by the CPU. If the CPU is not
executing in the enclave mode inside the enclave, #GP is raised. On the other
hand enclave code can make memory accesses both inside and outside of the
ELRANGE.

Enclave can only execute code inside the ELRANGE. Instructions that may cause
VMEXIT, IO instructions and instructions that require a privilege change are
prohibited inside the enclave. Interrupts and exceptions always cause enclave
to exit and jump to an address outside the enclave given when the enclave is
entered by using the leaf instruction ENCLS(EENTER).

Data types
----------

The protected memory range contains the following data:

* **Enclave Page Cache (EPC):** protected pages
* **Enclave Page Cache Map (EPCM):** a database that describes the state of the
  pages and link them to an enclave.

EPC has a number of different types of pages:

* **SGX Enclave Control Structure (SECS)**: describes the global
  properties of an enclave.
* **Regular (REG):** code and data pages in the ELRANGE.
* **Thread Control Structure (TCS):** pages that define entry points inside an
  enclave. The enclave can only be entered through these entry points and each
  can host a single hardware thread at a time.
* **Version Array (VA)**: 64-bit version numbers for pages that have been
  swapped outside the enclave. Each page contains 512 version numbers.

Launch control
--------------

To launch an enclave, two structures must be provided for ENCLS(EINIT):

1. **SIGSTRUCT:** signed measurement of the enclave binary.
2. **EINITTOKEN:** a cryptographic token CMAC-signed with a AES256-key called
   *launch key*, which is re-generated for each boot cycle.

The CPU holds a SHA256 hash of a 3072-bit RSA public key inside
IA32_SGXLEPUBKEYHASHn MSRs. Enclaves with a SIGSTRUCT that is signed with this
key do not require a valid EINITTOKEN and can be authorized with special
privileges. One of those privileges is ability to acquire the launch key with
ENCLS(EGETKEY).

**IA32_FEATURE_CONTROL[17]** is used by to BIOS configure whether
IA32_SGXLEPUBKEYHASH MSRs are read-only or read-write before locking the
feature control register and handing over control to the operating system.

Enclave construction
--------------------

The construction is started by filling out the SECS that contains enclave
address range, privileged attributes and measurement of TCS and REG pages (pages
that will be mapped to the address range) among the other things. This structure
is passed out to the ENCLS(ECREATE) together with a physical address of a page
in EPC that will hold the SECS.

Then pages are added with ENCLS(EADD) and measured with ENCLS(EEXTEND).  Finally
enclave is initialized with ENCLS(EINIT). ENCLS(INIT) checks that the SIGSTRUCT
is signed with the contained public key and that the supplied EINITTOKEN is
valid (CMAC'd with the launch key). If these hold, the enclave is successfully
initialized.

Swapping pages
--------------

Enclave pages can be swapped out with ENCLS(EWB) to the unprotected memory. In
addition to the EPC page, ENCLS(EWB) takes in a VA page and address for PCMD
structure (Page Crypto MetaData) as input. The VA page will seal a version
number for the page. PCMD is 128 byte structure that contains tracking
information for the page, most importantly its MAC. With these structures the
enclave is sealed and rollback protected while it resides in the unprotected
memory.

Before the page can be swapped out it must not have any active TLB references.
By using ENCLS(EBLOCK) instructions no new TLB entries can be created to it.
After this the a counter called *epoch* associated hardware threads inside the
enclave is increased with ENCLS(ETRACK). After all the threads from the previous
epoch have exited the page can be safely swapped out.

An enclave memory access to a swapped out pages will cause #PF. #PF handler can
fault the page back by using ENCLS(ELDU).

Driver internals
================

Launching enclaves
------------------

For privileged enclaves the launch is performed simply by submitting the
SIGSTRUCT for that enclave to ENCLS(EINIT). For unprivileged enclaves the
driver hosts a process in ring-3 that hosts a launch enclave signed with a key
supplied for kbuild.

The current implementation of the launch enclave generates a token for any
enclave. In the future it could be potentially extended to have ways to
configure policy what can be lauched.

The driver will fail to initialize if it cannot start its own launch enclave.
A user space application can submit a SIGSTRUCT instance through the ioctl API.
The kernel will take care of the rest.

This design assures that the Linux kernel has always full control, which
enclaves get to launch and which do not, even if the public key MSRs are
read-only. Having launch intrinsics inside the kernel also enables easy
development of enclaves without necessarily needing any heavy weight SDK.
Having a low-barrier to implement enclaves could make sense for example for
system daemons where amount of dependecies ought to be minimized.

Swapper
-------

The driver has a trivial implementation of swapping code in sgx_page_cache.c,
which swaps pages from processes and enclaves in a round-robin fashion. In
future it would probably make sense to find a way to let the Linux swapper to
pick the victim pages but it is not currently doable because EPC pages do not
have associated page structures.

SGX uapi
========

.. kernel-doc:: drivers/platform/x86/intel_sgx/sgx_ioctl.c
   :functions: sgx_ioc_enclave_create
               sgx_ioc_enclave_add_page
               sgx_ioc_enclave_init

.. kernel-doc:: arch/x86/include/uapi/asm/sgx.h

References
==========

* System Programming Manual: 39.1.4 Intel® SGX Launch Control Configuration
