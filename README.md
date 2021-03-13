# bofs
Cobalt Strike BOF projects

*more to come*:
 - aka 'smuggle' stash shellcode in signed PE, recalculate 3 key areas of PE without nullifying signature (signtool & sigcheck) 
   - separate loader for execution
   - use cases will be provided
  - aka 'smuggle_exec' (bof version of the C# code I wrote for the poc 'SharpSigExec')
    - loader/code execution for 'smuggle' 
    - decrypt then execute 
  - 'syncme'
    - dcsync privs for user   
