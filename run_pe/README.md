# Demo: RunPE
This is a demo project using _libpeconv_.<br/>
RunPE (aka Process Hollowing) is a well known technique allowing to injecting a new PE into a remote processes, imprersonating this process.
The given implementation works for PE 32bit as well as 64bit.<br/>

Supported injections:
-
If the loader was built as 32 bit:
<pre>
32 bit payload -> 32 bit target
</pre>
If the loader was built as 64 bit:
<pre>
64 bit payload -> 64 bit target
</pre>
It is also possible to inject from 64 bit loader 32 bit payload to 32 bit target, however, in this version of loader it is not implemented.
If you want to see how to do it, check my other RunPE implementation:<br/>
https://github.com/hasherezade/demos/tree/master/run_pe 

How to use the app:
-
Supply 2 commandline arguments:
<pre>
[payload_path] [*target_path]
* - optional
</pre>
If target path is not supplied, _calc.exe_ is used as the default target.

Compiled versions:
-
32bit: https://drive.google.com/uc?export=download&id=1ecRq0R3ABzkXELfyx95qxFjIsCCEFbEz <br/>
64bit: https://drive.google.com/uc?export=download&id=1ohcIvmMnFq5OgONaZXlkQQ2TkmJbpLhl <br/>
