## Highcall-Library - a usermode library primarily used for stealthy purposes.

* **Features on x86**
  * Process 
    * Enumerate modules
    * Enumerate hidden modules
    * Write/Read
    * Change memory protection
    * Suspend/resume
    * Allocate/deallocate
    * Manual map dlls
  * Modules
    * Acquire module's handle
    * Acquire module's export address
    * Load modules
  * Files
    * Read module information directly from disk
    * Read module export/arbitrary address from disk
    * Query the file information
  * System calls
    * Acquire system function index
    * OS Dynamic system calls
    * Easily implementable
    * Read module from disk
    * Various string helpers
    * Pattern searching
    * Detoured function calling
  * Other
    * Recover hooked functions, and call them
    * Search for arbitrary patterns within a process
    * String helpers
* **Features on x86_64**
  * Process 
    * Enumerate modules
    * Enumerate hidden modules
    * Write/Read
    * Change memory protection
    * Suspend/resume
    * Allocate/deallocate
  * Modules
    * Acquire module's handle
    * Acquire module's export address
    * Load modules
  * Files
    * Read module information directly from disk
    * Read module export/arbitrary address from disk
    * Query the file information
  * System calls
    * Acquire system function index
    * OS Dynamic system calls
    * Easily implementable
    * Read module from disk
    * Various string helpers
    * Pattern searching
    * Detoured function calling
  * Other
    * Recover hooked functions, and call them
    * Search for arbitrary patterns within a process
    * String helpers

Supported OS are Windows 7 (64bit), Windows 8 (64bit), Windows 8.1 (64bit), Windows 10 (64bit).
Supports x86/x64 VS compilers.
