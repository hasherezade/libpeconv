# Demo: RunPE
This is a demo project using _libpeconv_.<br/>
RunPE (aka Process Hollowing) is a well known technique allowing to injecting a new PE into a remote processes, imprersonating this process.
The given implementation works for PE 32bit as well as 64bit.<br/>

Supported injections:
-
If the loader was built as 32 bit:
```
32 bit payload -> 32 bit target
```
If the loader was built as 64 bit:
```
64 bit payload -> 64 bit target
32 bit payload -> 32 bit target
```

How to use the app:
-
Supply 2 commandline arguments:
```
[payload_path] [*target_path]
* - optional
```
If target path is not supplied, _calc.exe_ is used as the default target.

Compiled versions:
-
32bit: https://drive.google.com/uc?export=download&id=1ecRq0R3ABzkXELfyx95qxFjIsCCEFbEz <br/>
64bit: https://drive.google.com/uc?export=download&id=1ohcIvmMnFq5OgONaZXlkQQ2TkmJbpLhl <br/>
